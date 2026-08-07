// Deterministic dnlib metadata-normalizing round-trip.
//
// This is the FIRST-PASS .NET recovery: dnlib loads assemblies the CLR/ILSpy
// reject and re-emits a standards-conformant metadata layout, so a plain
// load-and-resave frequently fixes "Illegal tables in compressed metadata stream"
// on its own -- the common ConfuserEx-style metadata mangling. It runs with NO
// model in the loop; the agentic dotnet_analyst is the escalation for protections
// this does not resolve (string decryption, proxy-call / anti-tamper stripping).
//
// Usage: dotnet-script dnlib-roundtrip.csx -- <input> <output>
// Exit 0 iff <output> was written (a normalized module); non-zero otherwise.
#r "/opt/dnlib/dnlib.dll"
using System;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

if (Args.Count < 2) {
    Console.Error.WriteLine("usage: dnlib-roundtrip.csx -- <input> <output>");
    Environment.Exit(2);
}
var input = Args[0];
var output = Args[1];

ModuleDefMD mod;
try {
    mod = ModuleDefMD.Load(input);
} catch (Exception e) {
    Console.Error.WriteLine($"[dnlib-roundtrip] load failed: {e.GetType().Name}: {e.Message}");
    Environment.Exit(1);
    return;
}

void Write(bool preserve) {
    var opts = new ModuleWriterOptions(mod) { Logger = DummyLogger.NoThrowInstance };
    if (preserve)
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
    mod.Write(output, opts);
}

try {
    // Default: let dnlib rebuild the metadata tables (this is what normalizes an
    // illegal #~ stream). If a full rebuild throws on the obfuscator's structures,
    // fall back to preserving the original RIDs so the write still succeeds.
    try { Write(preserve: false); }
    catch (Exception e1) {
        Console.Error.WriteLine($"[dnlib-roundtrip] rebuild failed ({e1.GetType().Name}); preserving RIDs");
        Write(preserve: true);
    }
} catch (Exception e2) {
    Console.Error.WriteLine($"[dnlib-roundtrip] write failed: {e2.GetType().Name}: {e2.Message}");
    Environment.Exit(1);
    return;
}
Console.WriteLine($"[dnlib-roundtrip] wrote {output} (types={mod.Types.Count})");
