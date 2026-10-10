import Foundation
#if canImport(AriadC)
import AriadC
#endif

enum AriadExampleError: Error {
    case incompatibleABI(expected: UInt32, actual: UInt32)
    case call(operation: String, status: Int32)
}

struct AriadSessionRun<Value> {
    let result: Result<Value, Error>
    let shutdownStatus: Int32?
    let destroyStatus: Int32?
    // BUSY preserves ownership. INTERNAL does not establish safe handle reuse.
    let engineWithUnconfirmedCleanup: ariad_handle?
}

func requireAriadOK(_ status: Int32, operation: String) throws {
    guard status == Int32(ARIAD_OK) else {
        throw AriadExampleError.call(operation: operation, status: status)
    }
}

func ariadStatusName(_ status: Int32) -> String {
    guard let name = ariad_status_name(status) else {
        preconditionFailure("ariad_status_name returned NULL")
    }
    return String(cString: name)
}

private func validatePinnedH2(timeoutMilliseconds: UInt32) throws {
    let actualABI = ariad_abi_version()
    let expectedABI = UInt32(ARIAD_ABI_VERSION)
    guard actualABI == expectedABI else {
        throw AriadExampleError.incompatibleABI(expected: expectedABI, actual: actualABI)
    }
    guard timeoutMilliseconds > 0
        && timeoutMilliseconds <= UInt32(ARIAD_MAX_TIMEOUT_MS) else {
        throw AriadExampleError.call(
            operation: "timeout", status: Int32(ARIAD_ERROR_INVALID_ARGUMENT)
        )
    }
    try requireAriadOK(
        ariad_supported(UInt32(ARIAD_FEATURE_H2)) == 1
            ? Int32(ARIAD_OK) : Int32(ARIAD_ERROR_UNSUPPORTED),
        operation: "H2 capability"
    )
}

// Run on an application worker. Join all calls before operation returns.
// The session and its children must not escape operation.
func withPinnedH2Session<Value>(
    endpoint: String,
    tlsName: String,
    trustRootDER: Data,
    credential: Data,
    timeoutMilliseconds: UInt32 = 5_000,
    operation: (ariad_handle) throws -> Value
) -> AriadSessionRun<Value> {
    var engine: ariad_handle = 0
    let endpointBytes = Array(endpoint.utf8)
    let identityBytes = Array(tlsName.utf8)

    let result: Result<Value, Error> = Result {
        try validatePinnedH2(timeoutMilliseconds: timeoutMilliseconds)

        let createStatus = endpointBytes.withUnsafeBufferPointer { endpointBuffer in
            identityBytes.withUnsafeBufferPointer { identityBuffer in
                trustRootDER.withUnsafeBytes { (rootBuffer: UnsafeRawBufferPointer) in
                    ariad_engine_create(
                        endpointBuffer.baseAddress, endpointBuffer.count,
                        identityBuffer.baseAddress, identityBuffer.count,
                        rootBuffer.bindMemory(to: UInt8.self).baseAddress, rootBuffer.count,
                        &engine
                    )
                }
            }
        }
        try requireAriadOK(createStatus, operation: "engine_create")

        var session: ariad_handle = 0
        let connectStatus = credential.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            ariad_engine_connect(
                engine, buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count,
                timeoutMilliseconds, &session
            )
        }
        try requireAriadOK(connectStatus, operation: "engine_connect")
        return try operation(session)
    }

    guard engine != 0 else {
        return AriadSessionRun(
            result: result, shutdownStatus: nil, destroyStatus: nil,
            engineWithUnconfirmedCleanup: nil
        )
    }

    let shutdownStatus = ariad_engine_shutdown(engine, timeoutMilliseconds)
    let destroyStatus = ariad_engine_destroy(engine, timeoutMilliseconds)
    let invalidated = destroyStatus == Int32(ARIAD_OK)
        || destroyStatus == Int32(ARIAD_FORCED)
        || destroyStatus == Int32(ARIAD_ERROR_TRANSPORT)
        || destroyStatus == Int32(ARIAD_ERROR_INVALID_HANDLE)
    return AriadSessionRun(
        result: result,
        shutdownStatus: shutdownStatus,
        destroyStatus: destroyStatus,
        engineWithUnconfirmedCleanup: invalidated ? nil : engine
    )
}
