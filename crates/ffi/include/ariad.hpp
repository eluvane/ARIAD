#ifndef ARIAD_HPP
#define ARIAD_HPP

#include "ariad.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>

namespace ariad {

using status = std::int32_t;

inline const char *status_name(status value) noexcept {
    return ariad_status_name(value);
}

namespace detail {

enum class handle_kind : std::uint8_t { engine, session, stream, association };

struct lifetime {
    ariad_handle handle = 0;
    bool usable = true;
    bool children_valid = true;
    std::shared_ptr<lifetime> parent;

    [[nodiscard]] bool valid() const noexcept {
        const auto *current = this;
        while (current != nullptr) {
            if (current->handle == 0 || !current->usable ||
                (current->parent && !current->parent->children_valid)) {
                return false;
            }
            current = current->parent.get();
        }
        return true;
    }
};

inline bool preserves_ownership(status value) noexcept {
    return value == ARIAD_ERROR_BUSY || value == ARIAD_ERROR_INVALID_ARGUMENT;
}

inline void quarantine(lifetime &value) noexcept {
    value.usable = false;
    value.children_valid = false;
}

inline void quarantine_engine(lifetime &value) noexcept {
    auto *root = &value;
    while (root->parent) {
        root = root->parent.get();
    }
    quarantine(*root);
}

template <handle_kind Kind>
status destroy_native(ariad_handle handle, std::uint32_t timeout_ms) noexcept {
    if constexpr (Kind == handle_kind::engine) {
        return ariad_engine_destroy(handle, timeout_ms);
    } else if constexpr (Kind == handle_kind::session) {
        return ariad_session_destroy(handle);
    } else if constexpr (Kind == handle_kind::stream) {
        return ariad_stream_destroy(handle);
    } else {
        return ariad_association_destroy(handle);
    }
}

struct access;

}

template <detail::handle_kind Kind> class owner {
  public:
    owner() noexcept = default;
    owner(owner &&) noexcept = default;
    owner(const owner &) = delete;
    owner &operator=(const owner &) = delete;
    owner &operator=(owner &&) = delete;

    ~owner() noexcept {
        if (state_) {
            (void)destroy_impl(1000);
            // Scope exit cannot retain ownership for a later BUSY retry.
            state_->handle = 0;
            state_->children_valid = false;
        }
    }

    [[nodiscard]] ariad_handle native_handle() const noexcept {
        return state_ && state_->valid() ? state_->handle : 0;
    }

    explicit operator bool() const noexcept {
        return native_handle() != 0;
    }

    [[nodiscard]] status destroy() noexcept {
        return destroy_impl(1000);
    }

  private:
    explicit owner(std::shared_ptr<detail::lifetime> state) noexcept : state_(std::move(state)) {}

    status destroy_impl(std::uint32_t timeout_ms) noexcept {
        // Destroy can retry a retained handle that ordinary calls cannot borrow.
        const auto handle = state_ ? state_->handle : 0;
        if (handle == 0) {
            if (state_) {
                state_->handle = 0;
                state_->children_valid = false;
            }
            return ARIAD_ERROR_INVALID_HANDLE;
        }
        const auto value = detail::destroy_native<Kind>(handle, timeout_ms);
        if (!detail::preserves_ownership(value)) {
            // Only these outcomes establish native invalidation.
            const bool invalidated = [value] {
                if (value == ARIAD_OK || value == ARIAD_ERROR_INVALID_HANDLE) {
                    return true;
                }
                if constexpr (Kind == detail::handle_kind::engine) {
                    return value == ARIAD_FORCED || value == ARIAD_ERROR_TRANSPORT;
                }
                return false;
            }();
            detail::quarantine(*state_);
            if (invalidated) {
                state_->handle = 0;
            } else {
                detail::quarantine_engine(*state_);
            }
        }
        return value;
    }

    std::shared_ptr<detail::lifetime> state_;
    friend struct detail::access;
};

using engine = owner<detail::handle_kind::engine>;
using session = owner<detail::handle_kind::session>;
using stream = owner<detail::handle_kind::stream>;
using association = owner<detail::handle_kind::association>;

template <class T> struct result {
    status code = ARIAD_ERROR_INVALID_HANDLE;
    T value;
};

namespace detail {

struct access {
    template <handle_kind Kind>
    static std::shared_ptr<lifetime> state(const owner<Kind> &value) noexcept {
        return value.state_;
    }

    template <handle_kind Kind> static owner<Kind> adopt(std::shared_ptr<lifetime> state) noexcept {
        return owner<Kind>(std::move(state));
    }

    static status destroy(engine &value, std::uint32_t timeout_ms) noexcept {
        return value.destroy_impl(timeout_ms);
    }

    template <handle_kind Kind>
    static void invalidate_children(owner<Kind> &value, status code) noexcept {
        if (value.state_ && !preserves_ownership(code)) {
            value.state_->children_valid = false;
            if (code == ARIAD_ERROR_INVALID_HANDLE) {
                value.state_->handle = 0;
            } else if (code != ARIAD_OK && code != ARIAD_FORCED && code != ARIAD_ERROR_TRANSPORT) {
                quarantine_engine(*value.state_);
            }
        }
    }

    template <handle_kind Kind>
    static void observe_status(owner<Kind> &value, status code) noexcept {
        if (value.state_ && code == ARIAD_ERROR_INTERNAL) {
            quarantine_engine(*value.state_);
        }
    }
};

template <handle_kind Kind, handle_kind ParentKind, class Create>
result<owner<Kind>> create_child(owner<ParentKind> &parent, Create create) {
    if (!parent) {
        return {ARIAD_ERROR_INVALID_HANDLE, owner<Kind>{}};
    }
    auto state = std::make_shared<lifetime>();
    state->parent = access::state(parent);
    const auto code = create(parent.native_handle(), &state->handle);
    access::observe_status(parent, code);
    if (code != ARIAD_OK) {
        return {code, owner<Kind>{}};
    }
    return {code, access::adopt<Kind>(std::move(state))};
}

}

[[nodiscard]] inline status destroy(engine &value, std::uint32_t timeout_ms) noexcept {
    return detail::access::destroy(value, timeout_ms);
}

[[nodiscard]] inline status shutdown(engine &value, std::uint32_t timeout_ms) noexcept {
    if (!value) {
        return ARIAD_ERROR_INVALID_HANDLE;
    }
    const auto code = ariad_engine_shutdown(value.native_handle(), timeout_ms);
    detail::access::invalidate_children(value, code);
    return code;
}

[[nodiscard]] inline status close(session &value, std::uint32_t mode,
                                  std::uint32_t timeout_ms) noexcept {
    if (!value) {
        return ARIAD_ERROR_INVALID_HANDLE;
    }
    const auto code = ariad_session_close(value.native_handle(), mode, timeout_ms);
    detail::access::invalidate_children(value, code);
    return code;
}

[[nodiscard]] inline result<engine> create_engine(std::string_view endpoint,
                                                  std::string_view identity,
                                                  const std::uint8_t *trust_root_der,
                                                  std::size_t trust_root_len) {
    auto state = std::make_shared<detail::lifetime>();
    const auto code = ariad_engine_create(
        reinterpret_cast<const std::uint8_t *>(endpoint.data()), endpoint.size(),
        reinterpret_cast<const std::uint8_t *>(identity.data()), identity.size(), trust_root_der,
        trust_root_len, &state->handle);
    if (code != ARIAD_OK) {
        return {code, engine{}};
    }
    return {code, detail::access::adopt<detail::handle_kind::engine>(std::move(state))};
}

[[nodiscard]] inline result<session> connect(engine &parent, const std::uint8_t *credential,
                                             std::size_t credential_len, std::uint32_t timeout_ms) {
    return detail::create_child<detail::handle_kind::session>(
        parent, [&](ariad_handle handle, ariad_handle *output) {
            return ariad_engine_connect(handle, credential, credential_len, timeout_ms, output);
        });
}

[[nodiscard]] inline result<stream> open_stream(session &parent, std::string_view destination,
                                                std::uint32_t timeout_ms) {
    return detail::create_child<detail::handle_kind::stream>(parent, [&](ariad_handle handle,
                                                                         ariad_handle *output) {
        return ariad_session_open_stream(handle,
                                         reinterpret_cast<const std::uint8_t *>(destination.data()),
                                         destination.size(), timeout_ms, output);
    });
}

[[nodiscard]] inline result<association> open_datagram(session &parent,
                                                       std::string_view destination,
                                                       bool require_unreliable,
                                                       std::uint32_t timeout_ms) {
    return detail::create_child<detail::handle_kind::association>(
        parent, [&](ariad_handle handle, ariad_handle *output) {
            return ariad_session_open_datagram(
                handle, reinterpret_cast<const std::uint8_t *>(destination.data()),
                destination.size(), require_unreliable ? 1u : 0u, timeout_ms, output);
        });
}

}

#endif
