project(console NONE)

add_subdirectory(templates)

# build console classes
javac(pki-console-classes
    DEPENDS
        symkey-jar pki-cmsutil-jar pki-certsrv-jar
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${COMMONS_CLI_JAR}
        ${JAXRS_API_JAR}
        ${SLF4J_API_JAR}
        ${BASE_JAR} ${LDAPJDK_JAR} ${MMC_JAR}
        ${MMC_EN_JAR} ${NMCLF_JAR} ${NMCLF_EN_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

# package console classes and resources
jar(pki-console-jar
    DEPENDS
        pki-console-classes
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-console.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    INPUT_DIR
        ${CMAKE_CURRENT_SOURCE_DIR}
    FILES
        com/netscape/admin/certsrv/images/*.gif
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-console.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CONSOLE_JAR ${CMAKE_BINARY_DIR}/dist/pki-console.jar CACHE INTERNAL "pki-console jar file")
