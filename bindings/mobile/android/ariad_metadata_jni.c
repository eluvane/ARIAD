#include <ariad.h>
#include <jni.h>

JNIEXPORT jint JNICALL Java_org_ariad_integration_AriadMetadata_abiVersion(JNIEnv *environment,
                                                                           jobject receiver) {
    (void)environment;
    (void)receiver;
    return (jint)ariad_abi_version();
}

JNIEXPORT jint JNICALL Java_org_ariad_integration_AriadMetadata_protocolVersion(JNIEnv *environment,
                                                                                jobject receiver) {
    (void)environment;
    (void)receiver;
    return (jint)ariad_protocol_version();
}

JNIEXPORT jint JNICALL
Java_org_ariad_integration_AriadMetadata_h2BindingVersion(JNIEnv *environment, jobject receiver) {
    (void)environment;
    (void)receiver;
    return (jint)ariad_h2_binding_version();
}

JNIEXPORT jint JNICALL Java_org_ariad_integration_AriadMetadata_supported(JNIEnv *environment,
                                                                          jobject receiver,
                                                                          jint feature) {
    (void)environment;
    (void)receiver;
    return (jint)ariad_supported((uint32_t)feature);
}

JNIEXPORT jint JNICALL Java_org_ariad_integration_AriadMetadata_target(JNIEnv *environment,
                                                                       jobject receiver,
                                                                       jint target) {
    (void)environment;
    (void)receiver;
    return (jint)ariad_target((uint32_t)target);
}

JNIEXPORT jstring JNICALL Java_org_ariad_integration_AriadMetadata_statusName(JNIEnv *environment,
                                                                              jobject receiver,
                                                                              jint status) {
    (void)receiver;
    return (*environment)->NewStringUTF(environment, ariad_status_name((int32_t)status));
}
