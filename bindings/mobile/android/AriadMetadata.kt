package org.ariad.integration

object AriadMetadata {
    const val ABI_VERSION = AriadConstants.ABI_VERSION
    const val FEATURE_H2 = AriadConstants.FEATURE_H2
    const val FEATURE_H3 = AriadConstants.FEATURE_H3
    const val FEATURE_UDP_UNRELIABLE = AriadConstants.FEATURE_UDP_UNRELIABLE
    const val FEATURE_ECH = AriadConstants.FEATURE_ECH
    const val TARGET_IOS = AriadConstants.TARGET_IOS
    const val TARGET_ANDROID = AriadConstants.TARGET_ANDROID

    init {
        System.loadLibrary("ariad_mobile_metadata")
    }

    external fun abiVersion(): Int
    external fun protocolVersion(): Int
    external fun h2BindingVersion(): Int
    external fun supported(feature: Int): Int
    external fun target(target: Int): Int
    external fun statusName(status: Int): String
}
