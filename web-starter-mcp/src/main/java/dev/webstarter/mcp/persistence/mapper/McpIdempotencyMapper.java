package dev.webstarter.mcp.persistence.mapper;

import java.time.LocalDateTime;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import dev.webstarter.mcp.persistence.model.McpIdempotencyRecord;

@Mapper
public interface McpIdempotencyMapper {

    @Insert("""
            INSERT INTO mcp_idempotency_record (
                id, namespace_hash, tool_name, idempotency_key_hash, reservation_nonce,
                request_hash, status, created_at, expires_at
            ) VALUES (
                #{id}, #{namespaceHash}, #{toolName}, #{idempotencyKeyHash}, #{reservationNonce},
                #{requestHash}, #{status}, #{createdAt}, #{expiresAt}
            )
            AS incoming
            ON DUPLICATE KEY UPDATE
                reservation_nonce = IF(mcp_idempotency_record.expires_at <= incoming.created_at,
                    incoming.reservation_nonce, mcp_idempotency_record.reservation_nonce),
                request_hash = IF(mcp_idempotency_record.expires_at <= incoming.created_at,
                    incoming.request_hash, mcp_idempotency_record.request_hash),
                status = IF(mcp_idempotency_record.expires_at <= incoming.created_at,
                    'PENDING', mcp_idempotency_record.status),
                response_json = IF(mcp_idempotency_record.expires_at <= incoming.created_at,
                    NULL, mcp_idempotency_record.response_json),
                resource_id = IF(mcp_idempotency_record.expires_at <= incoming.created_at,
                    NULL, mcp_idempotency_record.resource_id),
                created_at = IF(mcp_idempotency_record.expires_at <= incoming.created_at,
                    incoming.created_at, mcp_idempotency_record.created_at),
                completed_at = IF(mcp_idempotency_record.expires_at <= incoming.created_at,
                    NULL, mcp_idempotency_record.completed_at),
                expires_at = IF(mcp_idempotency_record.expires_at <= incoming.created_at,
                    incoming.expires_at, mcp_idempotency_record.expires_at)
            """)
    int claim(McpIdempotencyRecord record);

    @Select("""
            SELECT id, namespace_hash, tool_name, idempotency_key_hash, reservation_nonce, request_hash,
                   status, response_json, resource_id, created_at, completed_at, expires_at
              FROM mcp_idempotency_record
             WHERE namespace_hash = #{namespaceHash}
               AND tool_name = #{toolName}
               AND idempotency_key_hash = #{keyHash}
             FOR UPDATE
            """)
    @Results(id = "mcpIdempotencyRecord", value = {
            @Result(column = "namespace_hash", property = "namespaceHash"),
            @Result(column = "tool_name", property = "toolName"),
            @Result(column = "idempotency_key_hash", property = "idempotencyKeyHash"),
            @Result(column = "reservation_nonce", property = "reservationNonce"),
            @Result(column = "request_hash", property = "requestHash"),
            @Result(column = "response_json", property = "responseJson"),
            @Result(column = "resource_id", property = "resourceId"),
            @Result(column = "created_at", property = "createdAt"),
            @Result(column = "completed_at", property = "completedAt"),
            @Result(column = "expires_at", property = "expiresAt")
    })
    McpIdempotencyRecord findForUpdate(
            @Param("namespaceHash") String namespaceHash,
            @Param("toolName") String toolName,
            @Param("keyHash") String keyHash);

    @Update("""
            UPDATE mcp_idempotency_record
               SET status = 'COMPLETED',
                   response_json = CAST(#{responseJson} AS JSON),
                   resource_id = #{resourceId},
                   completed_at = #{completedAt},
                   expires_at = #{expiresAt}
             WHERE namespace_hash = #{namespaceHash}
               AND tool_name = #{toolName}
               AND idempotency_key_hash = #{keyHash}
               AND reservation_nonce = #{reservationNonce}
               AND status = 'PENDING'
            """)
    int complete(
            @Param("namespaceHash") String namespaceHash,
            @Param("toolName") String toolName,
            @Param("keyHash") String keyHash,
            @Param("reservationNonce") String reservationNonce,
            @Param("responseJson") String responseJson,
            @Param("resourceId") String resourceId,
            @Param("completedAt") LocalDateTime completedAt,
            @Param("expiresAt") LocalDateTime expiresAt);

    @Delete("""
            DELETE FROM mcp_idempotency_record
             WHERE expires_at <= #{now}
             ORDER BY id
             LIMIT #{limit}
            """)
    int deleteExpiredBatch(@Param("now") LocalDateTime now, @Param("limit") int limit);
}
