const HelpStrings = @This();

const std = @import("std");
const Config = @import("Config.zig");

/// The "helpgen" exe.
exe: *std.Build.Step.Compile,

/// The output path for the help strings.
output: std.Build.LazyPath,

pub fn init(b: *std.Build, cfg: *const Config) !HelpStrings {
    // On Windows hosts, helpgen fails (ftruncate on stdout not supported),
    // and we don't need real help strings for trolley anyway.
    // Provide a stub module with empty structs so @hasDecl checks return false.
    if (b.graph.host.result.os.tag == .windows) {
        const wf = b.addWriteFiles();
        const output = wf.add("helpgen.zig",
            \\// Stub help strings for Windows builds
            \\pub const Config = struct {};
            \\pub const Action = struct {};
            \\pub const KeybindAction = struct {};
            \\
        );
        return .{
            .exe = undefined,
            .output = output,
        };
    }

    const exe = b.addExecutable(.{
        .name = "helpgen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/helpgen.zig"),
            .target = b.graph.host,
            .strip = false,
            .omit_frame_pointer = false,
            .unwind_tables = .sync,
        }),
    });

    const help_config = config: {
        var copy = cfg.*;
        copy.exe_entrypoint = .helpgen;
        break :config copy;
    };
    const options = b.addOptions();
    try help_config.addOptions(options);
    exe.root_module.addOptions("build_options", options);

    const help_run = b.addRunArtifact(exe);

    // Generated Zig files have to end with .zig
    const wf = b.addWriteFiles();
    const output = wf.addCopyFile(help_run.captureStdOut(), "helpgen.zig");

    return .{
        .exe = exe,
        .output = output,
    };
}

/// Add the "help_strings" import.
pub fn addImport(self: *const HelpStrings, step: *std.Build.Step.Compile) void {
    self.output.addStepDependencies(&step.step);
    step.root_module.addAnonymousImport("help_strings", .{
        .root_source_file = self.output,
    });
}

/// Install the help exe
pub fn install(self: *const HelpStrings) void {
    self.exe.step.owner.installArtifact(self.exe);
}
