package dev.webstarter.admin.config;

import java.lang.reflect.Array;
import java.util.List;

import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.BeanDescription;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.SerializationConfig;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.databind.ser.BeanPropertyWriter;
import tools.jackson.databind.ser.ValueSerializerModifier;
import tools.jackson.databind.ser.std.StdSerializer;

/**
 * Keeps database identifiers opaque at the browser boundary.
 *
 * <p>JavaScript cannot exactly represent every {@code long}. Only properties whose names carry
 * identifier semantics ({@code id}, {@code *Id}, or {@code *Ids}) are written as decimal strings;
 * counters, page metadata, versions, and durations remain JSON numbers.
 */
@Configuration(proxyBeanMethods = false)
public class WebIdJsonConfiguration {

    @Bean
    JsonMapperBuilderCustomizer webIdJsonMapperBuilderCustomizer() {
        return builder -> {
            SimpleModule module = new SimpleModule("web-starter-opaque-identifiers");
            module.setSerializerModifier(new OpaqueIdentifierSerializerModifier());
            builder.addModule(module);
        };
    }

    private static final class OpaqueIdentifierSerializerModifier extends ValueSerializerModifier {

        private static final ValueSerializer<Object> SCALAR_ID_SERIALIZER = new ScalarIdSerializer();
        private static final ValueSerializer<Object> ID_COLLECTION_SERIALIZER = new IdCollectionSerializer();

        @Override
        public List<BeanPropertyWriter> changeProperties(
                SerializationConfig config,
                BeanDescription.Supplier beanDescription,
                List<BeanPropertyWriter> properties) {
            for (BeanPropertyWriter property : properties) {
                JavaType type = property.getType();
                if (isScalarIdName(property.getName()) && isLong(type)) {
                    assign(property, SCALAR_ID_SERIALIZER);
                }
                else if (isIdCollectionName(property.getName()) && isLongContainer(type)) {
                    assign(property, ID_COLLECTION_SERIALIZER);
                }
            }
            return properties;
        }

        private static void assign(BeanPropertyWriter property, ValueSerializer<Object> serializer) {
            if (!property.hasSerializer()) {
                property.assignSerializer(serializer);
            }
        }

        private static boolean isLong(JavaType type) {
            return type.hasRawClass(Long.class) || type.hasRawClass(long.class);
        }

        private static boolean isLongContainer(JavaType type) {
            return (type.isCollectionLikeType() || type.isArrayType())
                    && type.getContentType() != null
                    && isLong(type.getContentType());
        }

        private static boolean isScalarIdName(String name) {
            return "id".equals(name) || name.endsWith("Id");
        }

        private static boolean isIdCollectionName(String name) {
            return "ids".equals(name) || name.endsWith("Ids");
        }
    }

    private static final class ScalarIdSerializer extends StdSerializer<Object> {

        private ScalarIdSerializer() {
            super(Object.class);
        }

        @Override
        public void serialize(Object value, JsonGenerator generator, SerializationContext context)
                throws JacksonException {
            generator.writeString(String.valueOf(value));
        }
    }

    private static final class IdCollectionSerializer extends StdSerializer<Object> {

        private IdCollectionSerializer() {
            super(Object.class);
        }

        @Override
        public void serialize(Object value, JsonGenerator generator, SerializationContext context)
                throws JacksonException {
            generator.writeStartArray(value);
            if (value instanceof Iterable<?> iterable) {
                for (Object element : iterable) {
                    writeElement(element, generator, context);
                }
            }
            else if (value.getClass().isArray()) {
                for (int index = 0; index < Array.getLength(value); index++) {
                    writeElement(Array.get(value, index), generator, context);
                }
            }
            generator.writeEndArray();
        }

        private static void writeElement(
                Object element,
                JsonGenerator generator,
                SerializationContext context) throws JacksonException {
            if (element == null) {
                context.defaultSerializeNullValue(generator);
            }
            else {
                generator.writeString(String.valueOf(element));
            }
        }
    }
}
