const std = @import("std");
const windows = std.os.windows;

// Export any constants or functions we need from the Windows API so
// we can just import one file.
pub const kernel32 = windows.kernel32;
pub const unexpectedError = windows.unexpectedError;
pub const OpenFile = windows.OpenFile;
pub const CloseHandle = windows.CloseHandle;
pub const GetCurrentProcessId = windows.GetCurrentProcessId;
pub const SetHandleInformation = windows.SetHandleInformation;
pub const DWORD = windows.DWORD;
pub const FILE_ATTRIBUTE_NORMAL = windows.FILE_ATTRIBUTE_NORMAL;
pub const FILE_FLAG_OVERLAPPED = windows.FILE_FLAG_OVERLAPPED;
pub const FILE_SHARE_READ = windows.FILE_SHARE_READ;
pub const GENERIC_READ = windows.GENERIC_READ;
pub const HANDLE = windows.HANDLE;
pub const HANDLE_FLAG_INHERIT = windows.HANDLE_FLAG_INHERIT;
pub const INFINITE = windows.INFINITE;
pub const INVALID_HANDLE_VALUE = windows.INVALID_HANDLE_VALUE;
pub const OPEN_EXISTING = windows.OPEN_EXISTING;
pub const PIPE_ACCESS_OUTBOUND = windows.PIPE_ACCESS_OUTBOUND;
pub const PIPE_TYPE_BYTE = windows.PIPE_TYPE_BYTE;
pub const PROCESS_INFORMATION = windows.PROCESS_INFORMATION;
pub const S_OK = windows.S_OK;
pub const SECURITY_ATTRIBUTES = windows.SECURITY_ATTRIBUTES;
pub const STARTUPINFOW = windows.STARTUPINFOW;
pub const STARTF_USESTDHANDLES = windows.STARTF_USESTDHANDLES;
pub const SYNCHRONIZE = windows.SYNCHRONIZE;
pub const WAIT_FAILED = windows.WAIT_FAILED;
pub const FALSE = windows.FALSE;
pub const TRUE = windows.TRUE;

pub const exp = struct {
    pub const HPCON = windows.LPVOID;

    pub const CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    pub const EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    pub const LPPROC_THREAD_ATTRIBUTE_LIST = ?*anyopaque;
    pub const FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000;

    pub const STATUS_PENDING = 0x00000103;
    pub const STILL_ACTIVE = STATUS_PENDING;

    pub const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100;
    pub const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000;

    pub const STARTUPINFOEX = extern struct {
        StartupInfo: windows.STARTUPINFOW,
        lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST,
    };

    pub const kernel32 = struct {
        pub extern "kernel32" fn CreatePipe(
            hReadPipe: *windows.HANDLE,
            hWritePipe: *windows.HANDLE,
            lpPipeAttributes: ?*const windows.SECURITY_ATTRIBUTES,
            nSize: windows.DWORD,
        ) callconv(.winapi) windows.BOOL;
        // Not pub: these bypass the owner tracking in `conpty`, and they take a
        // bare HPCON so nothing would catch the mistake. Go through `conpty`.
        extern "kernel32" fn CreatePseudoConsole(
            size: windows.COORD,
            hInput: windows.HANDLE,
            hOutput: windows.HANDLE,
            dwFlags: windows.DWORD,
            phPC: *HPCON,
        ) callconv(.winapi) windows.HRESULT;
        extern "kernel32" fn ResizePseudoConsole(hPC: HPCON, size: windows.COORD) callconv(.winapi) windows.HRESULT;
        extern "kernel32" fn ClosePseudoConsole(hPC: HPCON) callconv(.winapi) void;
        pub extern "kernel32" fn InitializeProcThreadAttributeList(
            lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST,
            dwAttributeCount: windows.DWORD,
            dwFlags: windows.DWORD,
            lpSize: *windows.SIZE_T,
        ) callconv(.winapi) windows.BOOL;
        pub extern "kernel32" fn UpdateProcThreadAttribute(
            lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST,
            dwFlags: windows.DWORD,
            Attribute: windows.DWORD_PTR,
            lpValue: windows.PVOID,
            cbSize: windows.SIZE_T,
            lpPreviousValue: ?windows.PVOID,
            lpReturnSize: ?*windows.SIZE_T,
        ) callconv(.winapi) windows.BOOL;
        pub extern "kernel32" fn PeekNamedPipe(
            hNamedPipe: windows.HANDLE,
            lpBuffer: ?windows.LPVOID,
            nBufferSize: windows.DWORD,
            lpBytesRead: ?*windows.DWORD,
            lpTotalBytesAvail: ?*windows.DWORD,
            lpBytesLeftThisMessage: ?*windows.DWORD,
        ) callconv(.winapi) windows.BOOL;
        // Duplicated here because lpCommandLine is not marked optional in zig std
        pub extern "kernel32" fn CreateProcessW(
            lpApplicationName: ?windows.LPWSTR,
            lpCommandLine: ?windows.LPWSTR,
            lpProcessAttributes: ?*windows.SECURITY_ATTRIBUTES,
            lpThreadAttributes: ?*windows.SECURITY_ATTRIBUTES,
            bInheritHandles: windows.BOOL,
            dwCreationFlags: windows.DWORD,
            lpEnvironment: ?*anyopaque,
            lpCurrentDirectory: ?windows.LPWSTR,
            lpStartupInfo: *windows.STARTUPINFOW,
            lpProcessInformation: *windows.PROCESS_INFORMATION,
        ) callconv(.winapi) windows.BOOL;
        /// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcomputernamea
        pub extern "kernel32" fn GetComputerNameA(
            lpBuffer: windows.LPSTR,
            nSize: *windows.DWORD,
        ) callconv(.winapi) windows.BOOL;
    };

    /// ConPTY entry points, resolved at first use. The OS pseudoconsole is as
    /// old as the OS build and misses every fix made since, so prefer a
    /// conpty.dll bundled next to our executable.
    pub const conpty = struct {
        const log = std.log.scoped(.conpty);

        const Funcs = struct {
            create: @TypeOf(&exp.kernel32.CreatePseudoConsole),
            resize: @TypeOf(&exp.kernel32.ResizePseudoConsole),
            close: @TypeOf(&exp.kernel32.ClosePseudoConsole),
            /// Drops the reference that keeps the console host alive once the
            /// child owns it. Bundled-only; kernel32 has no such entry point.
            release: ?*const fn (hPC: HPCON) callconv(.winapi) windows.HRESULT,
        };

        var funcs: Funcs = .{
            .create = &exp.kernel32.CreatePseudoConsole,
            .resize = &exp.kernel32.ResizePseudoConsole,
            .close = &exp.kernel32.ClosePseudoConsole,
            .release = null,
        };

        var load_once = std.once(load);

        /// HRESULT is signed, so formatting one as hex prints a negative.
        pub fn errorCode(result: windows.HRESULT) u32 {
            return @bitCast(result);
        }

        fn load() void {
            const module = loadBundledModule() orelse return;

            // conpty.dll aliases the kernel32 names, so the signatures match.
            // All or nothing: a partial resolve means it isn't the DLL we think.
            const create = windows.kernel32.GetProcAddress(module, "CreatePseudoConsole");
            const resize = windows.kernel32.GetProcAddress(module, "ResizePseudoConsole");
            const close = windows.kernel32.GetProcAddress(module, "ClosePseudoConsole");
            if (create == null or resize == null or close == null) {
                log.warn("bundled conpty.dll is missing exports, using the OS console host", .{});
                _ = windows.kernel32.FreeLibrary(module);
                return;
            }

            // Optional: an older DLL without it still works, we just can't
            // hand the console host off to the child.
            const release = windows.kernel32.GetProcAddress(module, "ConptyReleasePseudoConsole");

            funcs = .{
                .create = @ptrCast(@alignCast(create.?)),
                .resize = @ptrCast(@alignCast(resize.?)),
                .close = @ptrCast(@alignCast(close.?)),
                .release = if (release) |r| @ptrCast(@alignCast(r)) else null,
            };
            log.info("using bundled conpty.dll", .{});
        }

        /// Load `conpty.dll` from our own directory, by explicit path so the
        /// search order can't hand us a different one. The flags constrain the
        /// DLL's own imports, which a full path alone doesn't.
        fn loadBundledModule() ?windows.HMODULE {
            const name = std.unicode.utf8ToUtf16LeStringLiteral("conpty.dll");

            // Not PATH_MAX_WIDE: that's 64 KB of stack.
            var buf: [4096:0]u16 = undefined;
            const len = windows.kernel32.GetModuleFileNameW(null, &buf, buf.len);
            if (len == 0) {
                log.warn("using the OS console host (no executable path)", .{});
                return null;
            }
            if (len >= buf.len) {
                log.warn("using the OS console host (executable path too long)", .{});
                return null;
            }

            var dir_len: usize = len;
            while (dir_len > 0) : (dir_len -= 1) {
                const c = buf[dir_len - 1];
                if (c == '\\' or c == '/') break;
            } else {
                log.warn("using the OS console host (executable path has no directory)", .{});
                return null;
            }

            if (dir_len + name.len >= buf.len) {
                log.warn("using the OS console host (directory path too long)", .{});
                return null;
            }
            @memcpy(buf[dir_len..][0..name.len], name);
            buf[dir_len + name.len] = 0;

            const path = buf[0 .. dir_len + name.len :0];
            return windows.kernel32.LoadLibraryExW(
                path.ptr,
                null,
                exp.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | exp.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
            ) orelse {
                // No DLL beside us is the ordinary unbundled build; one that is
                // there but won't load is a broken install worth hearing about.
                // Ask the filesystem which it is — the load error can't tell us,
                // since a missing dependency reports the same code as a missing
                // file. Read the error first: the probe overwrites it.
                const err = windows.kernel32.GetLastError();
                const attrs = windows.kernel32.GetFileAttributesW(path.ptr);
                if (attrs == windows.INVALID_FILE_ATTRIBUTES) {
                    log.info("using the OS console host (no bundled conpty.dll)", .{});
                } else {
                    log.warn("using the OS console host (conpty.dll did not load, error {})", .{
                        @intFromEnum(err),
                    });
                }
                return null;
            };
        }

        /// Which implementation owns a given HPCON.
        pub const Owner = enum { bundled, os };

        /// A pseudoconsole and the implementation that created it. Resize and
        /// close have to reach that same one, so they travel as one value.
        pub const PseudoConsole = struct {
            handle: HPCON,
            owner: Owner,
        };

        /// On failure `pc` holds nothing to close; only a returned S_OK makes it
        /// valid.
        pub fn CreatePseudoConsole(
            size: windows.COORD,
            hInput: windows.HANDLE,
            hOutput: windows.HANDLE,
            dwFlags: windows.DWORD,
            pc: *PseudoConsole,
        ) windows.HRESULT {
            load_once.call();

            if (funcs.create != &exp.kernel32.CreatePseudoConsole) {
                // A value the callee would never produce, so we can tell whether
                // it handed us a console to clean up before falling back.
                const unset: HPCON = @ptrFromInt(std.math.maxInt(usize));
                pc.handle = unset;
                const result = funcs.create(size, hInput, hOutput, dwFlags, &pc.handle);
                // S_OK, not merely a success code: the caller treats anything
                // else as a failure and returns without closing.
                if (result == windows.S_OK) {
                    pc.owner = .bundled;
                    return result;
                }
                if (pc.handle != unset) funcs.close(pc.handle);
                // Resolved exports don't prove a working implementation, and a
                // failed surface is worse than an old console host.
                log.warn(
                    "bundled conpty.dll create failed (0x{X:0>8}), using the OS console host",
                    .{errorCode(result)},
                );
            }

            const result = exp.kernel32.CreatePseudoConsole(size, hInput, hOutput, dwFlags, &pc.handle);
            pc.owner = .os;
            return result;
        }

        /// Hand the console host to the child, so closing doesn't wait on it.
        /// Only valid once the child owns the handle, and only the bundled
        /// implementation offers it.
        pub fn releaseReference(pc: PseudoConsole) void {
            if (pc.owner != .bundled) return;
            load_once.call();
            const release = funcs.release orelse return;
            const result = release(pc.handle);
            if (result < 0) log.warn("conpty release failed (0x{X:0>8})", .{errorCode(result)});
        }

        pub fn ResizePseudoConsole(pc: PseudoConsole, size: windows.COORD) windows.HRESULT {
            // Cheap after the first call, and it's what publishes `funcs` to
            // whichever thread ends up here.
            load_once.call();
            return switch (pc.owner) {
                .bundled => funcs.resize(pc.handle, size),
                .os => exp.kernel32.ResizePseudoConsole(pc.handle, size),
            };
        }

        pub fn ClosePseudoConsole(pc: PseudoConsole) void {
            load_once.call();
            switch (pc.owner) {
                .bundled => funcs.close(pc.handle),
                .os => exp.kernel32.ClosePseudoConsole(pc.handle),
            }
        }
    };

    pub const PROC_THREAD_ATTRIBUTE_NUMBER = 0x0000FFFF;
    pub const PROC_THREAD_ATTRIBUTE_THREAD = 0x00010000;
    pub const PROC_THREAD_ATTRIBUTE_INPUT = 0x00020000;
    pub const PROC_THREAD_ATTRIBUTE_ADDITIVE = 0x00040000;

    pub const ProcThreadAttributeNumber = enum(windows.DWORD) {
        ProcThreadAttributePseudoConsole = 22,
        _,
    };

    /// Corresponds to the ProcThreadAttributeValue define in WinBase.h
    pub fn ProcThreadAttributeValue(
        comptime attribute: ProcThreadAttributeNumber,
        comptime thread: bool,
        comptime input: bool,
        comptime additive: bool,
    ) windows.DWORD {
        return (@intFromEnum(attribute) & PROC_THREAD_ATTRIBUTE_NUMBER) |
            (if (thread) PROC_THREAD_ATTRIBUTE_THREAD else 0) |
            (if (input) PROC_THREAD_ATTRIBUTE_INPUT else 0) |
            (if (additive) PROC_THREAD_ATTRIBUTE_ADDITIVE else 0);
    }

    pub const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = ProcThreadAttributeValue(.ProcThreadAttributePseudoConsole, false, true, false);
};
