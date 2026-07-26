from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import production_compose_policy as policy


DIGEST = "sha256:" + ("a" * 64)


def hardened_service(image: str) -> dict:
    return {
        "image": image,
        "user": "10001:10001",
        "read_only": True,
        "init": True,
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["ALL"],
        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
        "deploy": {
            "resources": {
                "limits": {"cpus": "1.0", "memory": 268435456, "pids": 128},
                "reservations": {"cpus": "0.1", "memory": 67108864},
            }
        },
    }


def valid_model() -> dict:
    app = hardened_service(f"registry.example/app@{DIGEST}")
    app["networks"] = {"app": None, "data": None}
    app["expose"] = ["8080", "8081"]
    app["environment"] = {
        "WEB_STARTER_MANAGEMENT_USERNAME": "starter_ops",
        "WEB_STARTER_MANAGEMENT_PASSWORD": "operations-password-0123456789abcdef",
        "WEB_STARTER_GIT_COMMIT": "a" * 40,
        "WEB_STARTER_SHUTDOWN_PHASE_TIMEOUT": policy.EXPECTED_APP_SHUTDOWN_PHASE_TIMEOUT,
    }
    app["healthcheck"] = {
        "test": copy.deepcopy(policy.EXPECTED_HEALTHCHECK_TESTS["app"]),
        **copy.deepcopy(policy.EXPECTED_APP_HEALTHCHECK_TIMING),
    }
    nginx = hardened_service(f"registry.example/nginx@{DIGEST}")
    nginx["user"] = "101:101"
    nginx["networks"] = {"app": None}
    nginx["healthcheck"] = {"test": copy.deepcopy(policy.EXPECTED_HEALTHCHECK_TESTS["nginx"])}
    public = copy.deepcopy(nginx)
    public["command"] = copy.deepcopy(policy.EXPECTED_COMMANDS["mcp-public-nginx"])
    public["healthcheck"] = {
        "test": copy.deepcopy(policy.EXPECTED_HEALTHCHECK_TESTS["mcp-public-nginx"])
    }
    public["volumes"] = [
        {
            "type": "bind",
            "source": "/run/cert",
            "target": "/etc/nginx/tls/fullchain.pem",
            "read_only": True,
            "bind": {"create_host_path": False},
        },
        {
            "type": "bind",
            "source": "/run/key",
            "target": "/etc/nginx/tls/privkey.pem",
            "read_only": True,
            "bind": {"create_host_path": False},
        },
    ]
    public["ports"] = [
        {
            "mode": "ingress",
            "host_ip": "0.0.0.0",
            "published": "8443",
            "protocol": "tcp",
            "target": 8443,
        }
    ]
    nginx["ports"] = [
        {
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "published": "8088",
            "protocol": "tcp",
            "target": 8080,
        }
    ]
    return {
        "networks": {
            "app": {"name": "web-starter_app", "ipam": {}},
            "data": {"name": "web-starter_data", "ipam": {}, "internal": True},
        },
        "volumes": {
            "mysql-data": {"name": "web-starter_mysql-data"},
            "redis-data": {"name": "web-starter_redis-data"},
        },
        "services": {
            "mysql": {
                "image": f"mysql@{DIGEST}",
                "command": copy.deepcopy(policy.EXPECTED_COMMANDS["mysql"]),
                "healthcheck": {
                    "test": copy.deepcopy(policy.EXPECTED_HEALTHCHECK_TESTS["mysql"])
                },
                "security_opt": ["no-new-privileges:true"],
                "networks": {"data": None},
                "volumes": [
                    {
                        "type": "volume",
                        "source": "mysql-data",
                        "target": "/var/lib/mysql",
                        "volume": {},
                    }
                ],
            },
            "redis": {
                "image": f"redis@{DIGEST}",
                "command": [
                    "redis-server",
                    "--appendonly",
                    "yes",
                    "--requirepass",
                    "validation-password",
                ],
                "healthcheck": {
                    "test": copy.deepcopy(policy.EXPECTED_HEALTHCHECK_TESTS["redis"])
                },
                "security_opt": ["no-new-privileges:true"],
                "networks": {"data": None},
                "volumes": [
                    {
                        "type": "volume",
                        "source": "redis-data",
                        "target": "/data",
                        "volume": {},
                    }
                ],
            },
            "app": app,
            "nginx": nginx,
            "mcp-public-nginx": public,
        }
    }


def write_static_fixture(root: Path, app_dockerfile: str, nginx_dockerfile: str) -> None:
    nginx_directory = root / "deploy" / "nginx"
    nginx_directory.mkdir(parents=True)
    (root / "Dockerfile").write_text(app_dockerfile, encoding="utf-8")
    (nginx_directory / "Dockerfile").write_text(nginx_dockerfile, encoding="utf-8")
    nginx_configuration = """\
worker_processes auto;
pid /tmp/nginx.pid;
http {
    client_body_temp_path /tmp/client_temp;
    proxy_temp_path /tmp/proxy_temp;
    fastcgi_temp_path /tmp/fastcgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    scgi_temp_path /tmp/scgi_temp;
}
"""
    (nginx_directory / "nginx.conf").write_text(nginx_configuration, encoding="utf-8")
    (nginx_directory / "nginx-public.conf").write_text(nginx_configuration, encoding="utf-8")


class ProductionComposePolicyTest(unittest.TestCase):
    def test_rejects_non_object_compose_model(self) -> None:
        self.assertEqual(
            ["compose model must be a JSON object"],
            policy.validate_compose(None),  # type: ignore[arg-type]
        )

    def test_accepts_immutable_hardened_model(self) -> None:
        self.assertEqual([], policy.validate_compose(valid_model()))

    def test_requires_dedicated_operational_credentials_only_on_app(self) -> None:
        missing = valid_model()
        del missing["services"]["app"]["environment"]["WEB_STARTER_MANAGEMENT_PASSWORD"]
        weak = valid_model()
        weak["services"]["app"]["environment"]["WEB_STARTER_MANAGEMENT_PASSWORD"] = "short"
        leaked = valid_model()
        leaked["services"]["nginx"]["environment"] = {
            "WEB_STARTER_MANAGEMENT_USERNAME": "starter_ops"
        }

        missing_errors = policy.validate_compose(missing)
        weak_errors = policy.validate_compose(weak)
        leaked_errors = policy.validate_compose(leaked)

        self.assertTrue(any("management password" in error for error in missing_errors))
        self.assertTrue(any("management password" in error for error in weak_errors))
        self.assertTrue(any("belong only to app" in error for error in leaked_errors))

    def test_rejects_build_and_mutable_image(self) -> None:
        model = valid_model()
        model["services"]["app"]["build"] = {"context": "."}
        model["services"]["app"]["image"] = "registry.example/app:latest"

        errors = policy.validate_compose(model)

        self.assertTrue(any("must not contain build" in error for error in errors))
        self.assertTrue(any("immutable" in error for error in errors))

    def test_rejects_unexpected_logging_labels_and_environment_injection(self) -> None:
        model = valid_model()
        model["x-unknown"] = {"enabled": True}
        model["services"]["app"]["logging"] = {
            "driver": "syslog",
            "options": {"syslog-address": "tcp://collector.example.invalid:514"},
        }
        model["services"]["app"]["labels"] = {"untrusted": "value"}
        model["services"]["app"]["environment"]["JAVA_TOOL_OPTIONS"] = "-javaagent:/tmp/x.jar"

        errors = policy.validate_compose(model)

        self.assertTrue(any("unsupported top-level" in error for error in errors))
        self.assertTrue(any("unsupported service settings" in error for error in errors))
        self.assertTrue(any("unsupported environment variables" in error for error in errors))

    def test_rejects_root_writable_or_privileged_app(self) -> None:
        model = valid_model()
        app = model["services"]["app"]
        app["user"] = "0:0"
        app["read_only"] = False
        app["privileged"] = True
        app["cap_add"] = ["NET_ADMIN"]

        errors = policy.validate_compose(model)

        self.assertTrue(any("user must be exactly" in error for error in errors))
        self.assertTrue(any("read-only" in error for error in errors))
        self.assertTrue(any("privileged" in error for error in errors))
        self.assertTrue(any("capability may be added" in error for error in errors))

    def test_rejects_unbounded_tmpfs_and_missing_limits(self) -> None:
        model = valid_model()
        nginx = model["services"]["nginx"]
        nginx["tmpfs"] = ["/tmp:rw"]
        nginx["deploy"] = {}

        errors = policy.validate_compose(model)

        self.assertTrue(any("tmpfs lacks" in error for error in errors))
        self.assertTrue(any("CPU limit" in error for error in errors))
        self.assertTrue(any("memory limit" in error for error in errors))
        self.assertTrue(any("PID limit" in error for error in errors))

    def test_rejects_writable_tls_mount_or_public_config_drift(self) -> None:
        model = valid_model()
        public = model["services"]["mcp-public-nginx"]
        public["volumes"][0]["read_only"] = False
        public["command"] = ["nginx", "-g", "daemon off;"]

        errors = policy.validate_compose(model)

        self.assertTrue(any("must be read-only" in error for error in errors))
        self.assertTrue(any("approved production invocation" in error for error in errors))

    def test_rejects_device_and_host_ipc_access(self) -> None:
        model = valid_model()
        app = model["services"]["app"]
        app["devices"] = ["/dev/kvm:/dev/kvm"]
        app["device_cgroup_rules"] = ["c 10:232 rwm"]
        app["ipc"] = "host"

        errors = policy.validate_compose(model)

        self.assertTrue(any("device mappings" in error for error in errors))
        self.assertTrue(any("device cgroup" in error for error in errors))
        self.assertTrue(any("namespace override ipc" in error for error in errors))

    def test_rejects_unconfined_or_other_security_options(self) -> None:
        for option in ("seccomp:unconfined", "apparmor:unconfined", "label:disable"):
            with self.subTest(option=option):
                model = valid_model()
                model["services"]["app"]["security_opt"].append(option)

                errors = policy.validate_compose(model)

                self.assertTrue(any("security_opt must be exactly" in error for error in errors))

    def test_rejects_docker_socket_and_non_allowlisted_read_only_mounts(self) -> None:
        model = valid_model()
        model["services"]["app"]["volumes"] = [
            {
                "type": "bind",
                "source": "/var/run/docker.sock",
                "target": "/var/run/docker.sock",
                "read_only": True,
            },
            {
                "type": "bind",
                "source": "/etc/hosts",
                "target": "/etc/hosts",
                "read_only": True,
            },
        ]

        errors = policy.validate_compose(model)

        self.assertTrue(any("Docker socket" in error for error in errors))
        self.assertTrue(any("not allowlisted" in error for error in errors))

    def test_rejects_tmpfs_outside_tmp(self) -> None:
        model = valid_model()
        model["services"]["nginx"]["tmpfs"].append(
            "/run:rw,noexec,nosuid,nodev,size=1m"
        )

        errors = policy.validate_compose(model)

        self.assertTrue(any("exactly one /tmp" in error for error in errors))

    def test_rejects_volumes_from_mount_bypass(self) -> None:
        model = valid_model()
        model["services"]["app"]["volumes_from"] = ["mysql:ro"]
        model["services"]["nginx"]["use_api_socket"] = True
        model["services"]["app"]["develop"] = {
            "watch": [{"action": "sync", "path": ".", "target": "/app"}]
        }

        errors = policy.validate_compose(model)

        self.assertTrue(any("volumes_from" in error for error in errors))
        self.assertTrue(any("engine API socket" in error for error in errors))
        self.assertTrue(any("development sync/watch" in error for error in errors))

    def test_rejects_wildcard_empty_public_or_hostname_private_bind(self) -> None:
        for host in ("", "0.0.0.0", "::", "8.8.8.8", "internal.example"):
            with self.subTest(host=host):
                model = valid_model()
                model["services"]["nginx"]["ports"][0]["host_ip"] = host

                errors = policy.validate_compose(model)

                self.assertTrue(any("private port host_ip" in error for error in errors))

    def test_accepts_explicit_rfc1918_and_ipv6_ula_private_binds(self) -> None:
        for host in ("10.20.30.40", "172.16.4.5", "192.168.7.8", "fd00::12"):
            with self.subTest(host=host):
                model = valid_model()
                model["services"]["nginx"]["ports"][0]["host_ip"] = host

                self.assertEqual([], policy.validate_compose(model))

    def test_rejects_missing_and_extra_services(self) -> None:
        missing = valid_model()
        del missing["services"]["redis"]
        extra = valid_model()
        extra["services"]["debug"] = copy.deepcopy(extra["services"]["app"])

        missing_errors = policy.validate_compose(missing)
        extra_errors = policy.validate_compose(extra)

        self.assertTrue(any("required services are missing" in error for error in missing_errors))
        self.assertTrue(any("unexpected production services" in error for error in extra_errors))

    def test_rejects_topology_network_and_volume_drift(self) -> None:
        model = valid_model()
        model["networks"]["debug"] = {"name": "debug", "ipam": {}}
        model["networks"]["data"]["internal"] = False
        model["volumes"]["debug-data"] = {"name": "debug-data"}
        model["services"]["mcp-public-nginx"]["networks"]["data"] = None

        errors = policy.validate_compose(model)

        self.assertTrue(any("networks must contain exactly" in error for error in errors))
        self.assertTrue(any("internal:true" in error for error in errors))
        self.assertTrue(any("volumes must contain exactly" in error for error in errors))
        self.assertTrue(any("mcp-public-nginx: networks must be exactly app" in error for error in errors))

    def test_rejects_network_alias_static_address_and_external_network(self) -> None:
        model = valid_model()
        model["services"]["nginx"]["networks"]["app"] = {"aliases": ["surprise"]}
        model["networks"]["app"]["external"] = True
        model["networks"]["data"]["ipam"] = {"config": [{"subnet": "10.0.0.0/8"}]}

        errors = policy.validate_compose(model)

        self.assertTrue(any("network aliases" in error for error in errors))
        self.assertTrue(any("unsupported settings" in error for error in errors))
        self.assertTrue(any("custom IPAM" in error for error in errors))

    def test_rejects_every_namespace_override(self) -> None:
        for key, value in (
            ("network_mode", "host"),
            ("ipc", "host"),
            ("pid", "host"),
            ("userns_mode", "host"),
            ("cgroup", "host"),
            ("cgroup_parent", "/"),
            ("uts", "host"),
        ):
            with self.subTest(key=key):
                model = valid_model()
                model["services"]["app"][key] = value

                errors = policy.validate_compose(model)

                self.assertTrue(any(f"namespace override {key}" in error for error in errors))

    def test_rejects_gpu_device_requests_and_alternate_runtime(self) -> None:
        model = valid_model()
        app = model["services"]["app"]
        app["gpus"] = "all"
        app["device_requests"] = [{"capabilities": [["gpu"]]}]
        app["runtime"] = "nvidia"

        errors = policy.validate_compose(model)

        self.assertTrue(any("GPU access" in error for error in errors))
        self.assertTrue(any("device requests" in error for error in errors))
        self.assertTrue(any("alternate container runtimes" in error for error in errors))

    def test_rejects_deploy_gpu_replica_profile_and_scale_bypasses(self) -> None:
        model = valid_model()
        model["services"]["redis"]["deploy"] = {
            "resources": {"reservations": {"devices": [{"capabilities": ["gpu"]}]}}
        }
        model["services"]["app"]["deploy"]["replicas"] = 0
        model["services"]["nginx"]["profiles"] = ["optional"]
        model["services"]["mcp-public-nginx"]["scale"] = 0

        errors = policy.validate_compose(model)

        self.assertTrue(any("deploy overrides are forbidden" in error for error in errors))
        self.assertTrue(any("deploy must contain only" in error for error in errors))
        self.assertTrue(any("conditional Compose profiles" in error for error in errors))
        self.assertTrue(any("service scale overrides" in error for error in errors))

    def test_rejects_shell_command_entrypoint_and_command_drift(self) -> None:
        shell_model = valid_model()
        shell_model["services"]["redis"]["command"] = ["sh", "-c", "redis-server"]
        entrypoint_model = valid_model()
        entrypoint_model["services"]["app"]["entrypoint"] = ["/bin/sh", "-c"]
        drift_model = valid_model()
        drift_model["services"]["mysql"]["command"].append("--skip-grant-tables")

        shell_errors = policy.validate_compose(shell_model)
        entrypoint_errors = policy.validate_compose(entrypoint_model)
        drift_errors = policy.validate_compose(drift_model)

        self.assertTrue(any("shell-form commands" in error for error in shell_errors))
        self.assertTrue(any("entrypoint overrides" in error for error in entrypoint_errors))
        self.assertTrue(any("approved production invocation" in error for error in drift_errors))

    def test_rejects_lifecycle_hooks_configs_secrets_and_sysctls(self) -> None:
        model = valid_model()
        model["services"]["app"]["post_start"] = [{"command": ["id"]}]
        model["services"]["nginx"]["pre_stop"] = [{"command": ["sh", "-c", "id"]}]
        model["services"]["app"]["configs"] = [{"source": "runtime", "target": "/app/runtime"}]
        model["services"]["app"]["secrets"] = [{"source": "secret", "target": "/app/secret"}]
        model["services"]["redis"]["sysctls"] = {"kernel.core_pattern": "|/bin/sh"}
        model["configs"] = {"runtime": {"file": "/etc/hosts"}}
        model["secrets"] = {"secret": {"file": "/etc/shadow"}}

        errors = policy.validate_compose(model)

        self.assertTrue(any("lifecycle command hooks" in error for error in errors))
        self.assertTrue(any("Compose config mounts" in error for error in errors))
        self.assertTrue(any("Compose secret mounts" in error for error in errors))
        self.assertTrue(any("sysctl overrides" in error for error in errors))
        self.assertTrue(any("top-level configs" in error for error in errors))
        self.assertTrue(any("top-level Compose secrets" in error for error in errors))

    def test_rejects_network_override_and_implicit_shm_mount_bypasses(self) -> None:
        for key, value in (
            ("extra_hosts", ["host.docker.internal:host-gateway"]),
            ("links", ["mysql"]),
            ("external_links", ["outside:outside"]),
            ("dns", ["8.8.8.8"]),
            ("dns_search", ["example.test"]),
        ):
            with self.subTest(key=key):
                model = valid_model()
                model["services"]["app"][key] = value

                errors = policy.validate_compose(model)

                self.assertTrue(any(f"network override {key}" in error for error in errors))

        model = valid_model()
        model["services"]["app"]["shm_size"] = 67108864
        errors = policy.validate_compose(model)
        self.assertTrue(any("implicit /dev/shm" in error for error in errors))

    def test_rejects_healthcheck_command_drift_and_preserves_safe_mysql_quoting(self) -> None:
        self.assertEqual(
            'mysqladmin ping -h 127.0.0.1 -uroot --password="$${MYSQL_ROOT_PASSWORD}" --silent',
            valid_model()["services"]["mysql"]["healthcheck"]["test"][1],
        )
        model = valid_model()
        model["services"]["mysql"]["healthcheck"]["test"] = ["CMD-SHELL", "true"]

        errors = policy.validate_compose(model)

        self.assertTrue(any("healthcheck command" in error for error in errors))

    def test_rejects_app_startup_healthcheck_timing_drift(self) -> None:
        for key, value in (("start_interval", None), ("start_interval", "5s"), ("start_period", "60s")):
            with self.subTest(key=key, value=value):
                model = valid_model()
                if value is None:
                    model["services"]["app"]["healthcheck"].pop(key)
                else:
                    model["services"]["app"]["healthcheck"][key] = value

                errors = policy.validate_compose(model)

                self.assertTrue(any("40s governance restart evidence window" in error for error in errors))

    def test_rejects_app_shutdown_phase_timeout_drift(self) -> None:
        for value in (None, "30s", "0s"):
            with self.subTest(value=value):
                model = valid_model()
                environment = model["services"]["app"]["environment"]
                if value is None:
                    environment.pop("WEB_STARTER_SHUTDOWN_PHASE_TIMEOUT")
                else:
                    environment["WEB_STARTER_SHUTDOWN_PHASE_TIMEOUT"] = value

                errors = policy.validate_compose(model)

                self.assertTrue(any("graceful shutdown phase timeout" in error for error in errors))

    def test_rejects_surprise_missing_and_malformed_ports(self) -> None:
        surprise = valid_model()
        surprise["services"]["mysql"]["ports"] = [
            {"host_ip": "127.0.0.1", "published": "3306", "target": 3306}
        ]
        missing = valid_model()
        missing["services"]["mcp-public-nginx"]["ports"] = []
        malformed = valid_model()
        malformed["services"]["nginx"]["ports"][0].update(
            {"target": 80, "protocol": "udp", "published": "0"}
        )

        surprise_errors = policy.validate_compose(surprise)
        missing_errors = policy.validate_compose(missing)
        malformed_errors = policy.validate_compose(malformed)

        self.assertTrue(any("mysql: published ports are forbidden" in error for error in surprise_errors))
        self.assertTrue(any("exactly one published port" in error for error in missing_errors))
        self.assertTrue(any("must target 8080" in error for error in malformed_errors))
        self.assertTrue(any("tcp ingress" in error for error in malformed_errors))
        self.assertTrue(any("single valid port" in error for error in malformed_errors))

    def test_rejects_surprise_expose_and_public_hostname_bind(self) -> None:
        model = valid_model()
        model["services"]["redis"]["expose"] = ["6379"]
        model["services"]["mcp-public-nginx"]["ports"][0]["host_ip"] = "public.example"

        errors = policy.validate_compose(model)

        self.assertTrue(any("redis: exposed ports must be exactly none" in error for error in errors))
        self.assertTrue(any("public port host_ip" in error for error in errors))

    def test_requires_exact_tls_binds_and_create_host_path_false(self) -> None:
        missing = valid_model()
        missing["services"]["mcp-public-nginx"]["volumes"].pop()
        auto_create = valid_model()
        auto_create["services"]["mcp-public-nginx"]["volumes"][0]["bind"]["create_host_path"] = True
        same_source = valid_model()
        same_source["services"]["mcp-public-nginx"]["volumes"][1]["source"] = "/run/cert"

        missing_errors = policy.validate_compose(missing)
        auto_create_errors = policy.validate_compose(auto_create)
        same_source_errors = policy.validate_compose(same_source)

        self.assertTrue(any("mount targets must be exactly" in error for error in missing_errors))
        self.assertTrue(any("create_host_path:false" in error for error in auto_create_errors))
        self.assertTrue(any("distinct bind sources" in error for error in same_source_errors))

    def test_rejects_named_volume_source_or_options_drift(self) -> None:
        model = valid_model()
        mount = model["services"]["mysql"]["volumes"][0]
        mount["source"] = "host-root"
        mount["volume"] = {"nocopy": True}

        errors = policy.validate_compose(model)

        self.assertTrue(any("must use volume mysql-data" in error for error in errors))
        self.assertTrue(any("forbidden volume options" in error for error in errors))

    def test_requires_exactly_one_bounded_non_conflicting_tmpfs(self) -> None:
        duplicate = valid_model()
        duplicate["services"]["app"]["tmpfs"].append(
            "/tmp:rw,noexec,nosuid,nodev,size=1m"
        )
        conflict = valid_model()
        conflict["services"]["app"]["tmpfs"] = [
            "/tmp:rw,ro,noexec,nosuid,nodev,size=0"
        ]
        duplicated_option = valid_model()
        duplicated_option["services"]["app"]["tmpfs"] = [
            "/tmp:rw,rw,noexec,nosuid,nodev,size=1m"
        ]

        duplicate_errors = policy.validate_compose(duplicate)
        conflict_errors = policy.validate_compose(conflict)
        duplicated_errors = policy.validate_compose(duplicated_option)

        self.assertTrue(any("exactly one /tmp" in error for error in duplicate_errors))
        self.assertTrue(any("conflicting options" in error for error in conflict_errors))
        self.assertTrue(any("positive size" in error for error in conflict_errors))
        self.assertTrue(any("duplicated" in error for error in duplicated_errors))

    def test_rejects_non_numeric_or_non_positive_resource_limits(self) -> None:
        model = valid_model()
        limits = model["services"]["app"]["deploy"]["resources"]["limits"]
        limits["cpus"] = "many"
        limits["memory"] = 0
        limits["pids"] = -1

        errors = policy.validate_compose(model)

        self.assertTrue(any("positive CPU" in error for error in errors))
        self.assertTrue(any("positive memory" in error for error in errors))
        self.assertTrue(any("positive PID" in error for error in errors))

    def test_rejects_user_group_and_security_option_drift(self) -> None:
        model = valid_model()
        model["services"]["app"]["user"] = "999:999"
        model["services"]["mysql"]["user"] = "root"
        model["services"]["redis"]["group_add"] = ["0"]
        model["services"]["nginx"]["security_opt"].append("no-new-privileges:true")
        model["services"]["mcp-public-nginx"]["init"] = False

        errors = policy.validate_compose(model)

        self.assertTrue(any("user must be exactly" in error for error in errors))
        self.assertTrue(any("user override" in error for error in errors))
        self.assertTrue(any("supplemental groups" in error for error in errors))
        self.assertTrue(any("security_opt must be exactly" in error for error in errors))
        self.assertTrue(any("init:true" in error for error in errors))

    def test_static_check_uses_last_effective_user_not_comments_or_earlier_user(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_static_fixture(
                root,
                "FROM base\n# USER 10001:10001\nUSER root\n",
                "FROM base\nUSER 101:101\nUSER root\nEXPOSE 8080 8443\n",
            )

            errors = policy.validate_dockerfiles(root)

            self.assertTrue(any("final app stage" in error for error in errors))
            self.assertTrue(any("final stage must run as 101:101" in error for error in errors))

    def test_static_check_rejects_commented_or_overridden_nginx_tmp_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_static_fixture(
                root,
                "FROM base\nUSER 10001:10001\n",
                "FROM base\nUSER 101:101\nEXPOSE 8080 8443\n",
            )
            nginx_path = root / "deploy" / "nginx" / "nginx.conf"
            nginx_path.write_text(
                "# pid /tmp/nginx.pid;\npid /run/nginx.pid;\n"
                "# client_body_temp_path /tmp/client_temp;\n",
                encoding="utf-8",
            )

            errors = policy.validate_dockerfiles(root)

            self.assertTrue(any("PID file" in error for error in errors))
            self.assertTrue(any("client_body_temp_path" in error for error in errors))

    def test_static_check_rejects_privileged_expose_ranges_and_tmp_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_static_fixture(
                root,
                "FROM base\nUSER 10001:10001\n",
                "FROM base\nUSER 101:101\nEXPOSE 79-81/tcp 8443\n",
            )
            nginx_path = root / "deploy" / "nginx" / "nginx-public.conf"
            nginx_path.write_text(
                "pid /tmp/nginx.pid;\n"
                "client_body_temp_path /tmp/../var/client;\n"
                "proxy_temp_path /tmp/proxy;\n"
                "fastcgi_temp_path /tmp/fastcgi;\n"
                "uwsgi_temp_path /tmp/uwsgi;\n"
                "scgi_temp_path /tmp/scgi;\n",
                encoding="utf-8",
            )

            errors = policy.validate_dockerfiles(root)

            self.assertTrue(any("privileged listener ports" in error for error in errors))
            self.assertTrue(any("client_body_temp_path" in error for error in errors))

    def test_cli_emits_checksum_bound_machine_readable_summary(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            compose_path = Path(directory) / "production-compose.json"
            output_path = Path(directory) / "production-compose-policy.json"
            compose_path.write_text(json.dumps(valid_model()), encoding="utf-8")

            exit_code = policy.main(
                [
                    "--compose-json",
                    str(compose_path),
                    "--repository-root",
                    str(repository_root),
                    "--output",
                    str(output_path),
                ]
            )

            summary = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(0, exit_code)
            self.assertEqual("PASS", summary["status"])
            self.assertEqual(hashlib.sha256(compose_path.read_bytes()).hexdigest(), summary["composeSha256"])
            self.assertEqual([], summary["errors"])


if __name__ == "__main__":
    unittest.main()
