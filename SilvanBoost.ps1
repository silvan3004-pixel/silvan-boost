#Requires -Version 5.1
<#
    SILVAN BOOST - FPS Optimizer  v2.5.1
    Scans any Windows 10/11 PC and adapts the optimizations to its hardware
    (NVIDIA / AMD / Intel GPUs, Intel / AMD CPUs, desktops and laptops, SSD / HDD).

    - PC Scanner with gaming health check
    - 70+ reversible tweaks (FPS & latency, network, memory & storage, registry, debloat, privacy)
    - Every original value is backed up to %ProgramData%\SilvanBoost\backup.json before it is changed
    - A System Restore point is created before the first change of every session

    Start it with "Launch Silvan Boost.bat" (asks for administrator rights).
#>

param([switch]$NoElevate, [switch]$JustUpdated, [string]$LauncherPath)

$ErrorActionPreference = 'Continue'
$script:AppName    = 'Silvan Boost'
$script:AppVersion = '2.6.0'

# ------------------------------------------------------------------ elevation
$wid = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($wid)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if (-not $NoElevate) {
        try {
            Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden -ArgumentList @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
        } catch { }
    }
    exit
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SBNative {
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
    [DllImport("user32.dll", SetLastError = true)] public static extern bool SystemParametersInfo(int a, int p, int[] v, int f);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct DEVMODE {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
        public short dmSpecVersion; public short dmDriverVersion; public short dmSize; public short dmDriverExtra;
        public int dmFields; public int dmPositionX; public int dmPositionY; public int dmDisplayOrientation; public int dmDisplayFixedOutput;
        public short dmColor; public short dmDuplex; public short dmYResolution; public short dmTTOption; public short dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
        public short dmLogPixels; public int dmBitsPerPel; public int dmPelsWidth; public int dmPelsHeight;
        public int dmDisplayFlags; public int dmDisplayFrequency; public int dmICMMethod; public int dmICMIntent;
        public int dmMediaType; public int dmDitherType; public int dmReserved1; public int dmReserved2;
        public int dmPanningWidth; public int dmPanningHeight;
    }
    [DllImport("user32.dll", CharSet = CharSet.Ansi)] public static extern bool EnumDisplaySettings(string dev, int mode, ref DEVMODE dm);

    // returns { currentHz, maxHz, width, height } for the primary display
    public static int[] Refresh() {
        DEVMODE cur = new DEVMODE(); cur.dmSize = (short)Marshal.SizeOf(typeof(DEVMODE));
        int c = 0, m = 0;
        if (EnumDisplaySettings(null, -1, ref cur)) c = cur.dmDisplayFrequency;
        DEVMODE dm = new DEVMODE(); dm.dmSize = cur.dmSize;
        for (int i = 0; EnumDisplaySettings(null, i, ref dm); i++) {
            if (dm.dmPelsWidth == cur.dmPelsWidth && dm.dmPelsHeight == cur.dmPelsHeight && dm.dmDisplayFrequency > m) m = dm.dmDisplayFrequency;
        }
        if (m < c) m = c;
        return new int[] { c, m, cur.dmPelsWidth, cur.dmPelsHeight };
    }
    public static bool SetMouseAccel(bool on) {
        int[] v = on ? new int[] { 6, 10, 1 } : new int[] { 0, 0, 0 };
        return SystemParametersInfo(0x0004, 0, v, 0x03);
    }
}
'@

Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class SBRaw {
    [StructLayout(LayoutKind.Sequential)]
    struct RAWINPUTDEVICE { public ushort UsagePage; public ushort Usage; public uint Flags; public IntPtr Target; }
    [DllImport("user32.dll", SetLastError = true)] static extern bool RegisterRawInputDevices(RAWINPUTDEVICE[] d, uint n, uint size);
    [DllImport("user32.dll", SetLastError = true)] static extern bool SystemParametersInfo(int a, int p, IntPtr v, int f);
    static readonly long[] ring = new long[16384];
    static int idx = 0;
    // WPF window hook: counts WM_INPUT messages (one per mouse report) for the polling rate test
    public static IntPtr Hook(IntPtr hwnd, int msg, IntPtr w, IntPtr l, ref bool handled) {
        if (msg == 0x00FF) { ring[idx & 16383] = Stopwatch.GetTimestamp(); idx++; }
        return IntPtr.Zero;
    }
    public static int RateLast(int ms) {
        long lim = Stopwatch.GetTimestamp() - Stopwatch.Frequency * ms / 1000;
        int n = Math.Min(idx, 16384), c = 0;
        for (int i = 1; i <= n; i++) { if (ring[(idx - i) & 16383] >= lim) c++; else break; }
        return (int)((long)c * 1000 / ms);
    }
    static bool Reg(uint flags, IntPtr target) {
        RAWINPUTDEVICE[] d = new RAWINPUTDEVICE[1];
        d[0].UsagePage = 1; d[0].Usage = 2; d[0].Flags = flags; d[0].Target = target;
        return RegisterRawInputDevices(d, 1, (uint)Marshal.SizeOf(typeof(RAWINPUTDEVICE)));
    }
    public static bool Start(IntPtr hwnd) { idx = 0; return Reg(0x00000100, hwnd); }
    public static bool Stop() { return Reg(0x00000001, IntPtr.Zero); }
    public static bool SetMouseSpeed(int v) { return SystemParametersInfo(0x0071, 0, (IntPtr)v, 0x03); }
}
'@

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

public class SBStep {
    public string Type;   // down, up, press, mdown, mup, click, delay, text
    public int Vk;
    public int Button;    // 1 left, 2 right, 3 middle, 4 back, 5 forward
    public int Ms;
    public string Text;
}

public class SBBinding {
    public string Trigger;          // MOUSE_MIDDLE, MOUSE_BACK, MOUSE_FORWARD, KEY:CTRL+ALT:77
    public string Kind;             // remap, combo, text, macro, run, media, sniper, disable
    public int Vk;
    public int[] Vks;
    public string Text;
    public SBStep[] Steps;
    public string Repeat = "once";  // once, held, toggle
    public string Path;
    public string Media;
    public int Speed = 4;
    public bool IsSimple { get { return Kind == "remap" || Kind == "sniper" || Kind == "disable"; } }
}

public static class SBMacro {
    // ---------------- native
    delegate IntPtr HookProc(int code, IntPtr w, IntPtr l);
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr SetWindowsHookEx(int id, HookProc fn, IntPtr mod, uint tid);
    [DllImport("user32.dll")] static extern bool UnhookWindowsHookEx(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr CallNextHookEx(IntPtr h, int code, IntPtr w, IntPtr l);
    [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] static extern bool PostThreadMessage(uint tid, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] static extern int GetMessage(out MSG m, IntPtr h, uint a, uint b);
    [DllImport("user32.dll")] static extern bool PeekMessage(out MSG m, IntPtr h, uint a, uint b, uint remove);
    [DllImport("user32.dll")] static extern bool TranslateMessage(ref MSG m);
    [DllImport("user32.dll")] static extern IntPtr DispatchMessage(ref MSG m);
    [DllImport("user32.dll")] static extern short GetAsyncKeyState(int vk);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", SetLastError = true)] static extern uint SendInput(uint n, INPUT[] inputs, int size);
    [DllImport("user32.dll")] static extern uint MapVirtualKey(uint code, uint type);
    [DllImport("user32.dll")] static extern bool SystemParametersInfo(uint a, uint p, ref int v, uint f);
    [DllImport("user32.dll", EntryPoint = "SystemParametersInfo")] static extern bool SystemParametersInfoSet(uint a, uint p, IntPtr v, uint f);

    [StructLayout(LayoutKind.Sequential)] struct POINT { public int x, y; }
    [StructLayout(LayoutKind.Sequential)] struct MSG { public IntPtr hwnd; public uint message; public IntPtr w; public IntPtr l; public uint time; public POINT pt; }
    [StructLayout(LayoutKind.Sequential)] struct MSLL { public POINT pt; public uint mouseData; public uint flags; public uint time; public IntPtr extra; }
    [StructLayout(LayoutKind.Sequential)] struct KBDLL { public uint vk; public uint scan; public uint flags; public uint time; public IntPtr extra; }
    [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint flags; public uint time; public IntPtr extra; }
    [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort vk; public ushort scan; public uint flags; public uint time; public IntPtr extra; }
    [StructLayout(LayoutKind.Explicit)] struct INPUTUNION { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)] struct INPUT { public uint type; public INPUTUNION u; }

    // ---------------- state
    static volatile Dictionary<string, SBBinding> map = new Dictionary<string, SBBinding>(StringComparer.OrdinalIgnoreCase);
    public static volatile bool Enabled = true;
    public static volatile bool GameMode = false;
    public static volatile bool Recording = false;
    public static bool RecordDelays = true;
    public static string LastError = "";
    public static int Fired = 0;

    static Thread hookThread;
    static uint hookThreadId;
    static IntPtr mHook = IntPtr.Zero, kHook = IntPtr.Zero;
    static HookProc mProc, kProc;
    static readonly uint ownPid = (uint)Process.GetCurrentProcess().Id;
    static readonly HashSet<string> pressed = new HashSet<string>();
    static readonly Dictionary<int, string> keyTrig = new Dictionary<int, string>();
    static readonly Dictionary<string, CancellationTokenSource> running = new Dictionary<string, CancellationTokenSource>();
    static readonly HashSet<int> macroHeld = new HashSet<int>();
    static readonly List<SBStep> rec = new List<SBStep>();
    static readonly HashSet<int> recDown = new HashSet<int>();
    static readonly Stopwatch recSw = new Stopwatch();
    static long recLast = 0;
    static int savedSpeed = -1;

    // ---------------- public API
    public static bool OwnForeground { get { return ForegroundIsOwn(); } }
    public static bool IsRunning { get { return mHook != IntPtr.Zero && kHook != IntPtr.Zero; } }

    public static void SetBindings(SBBinding[] list) {
        var d = new Dictionary<string, SBBinding>(StringComparer.OrdinalIgnoreCase);
        if (list != null) foreach (var b in list) if (b != null && !string.IsNullOrEmpty(b.Trigger)) d[b.Trigger] = b;
        CancelAll();
        map = d;
    }

    static readonly object life = new object();

    // Hooks are only installed while something needs them (bindings in the active profile or the recorder),
    // so games without macros get zero extra input processing.
    public static void Start() {
        lock (life) {
            if (hookThread != null && hookThread.IsAlive) return;
            var ready = new ManualResetEvent(false);
            var t = new Thread(() => Loop(ready));
            t.IsBackground = true;
            t.Name = "SilvanBoostMacroHooks";
            hookThread = t;
            t.Start();
            ready.WaitOne(3000);
        }
    }

    public static void Stop() {
        CancelAll();
        RestoreSniper();
        lock (life) {
            var t = hookThread;
            if (t != null) {
                if (hookThreadId != 0) PostThreadMessage(hookThreadId, 0x0012, IntPtr.Zero, IntPtr.Zero);
                t.Join(1500);
            }
            hookThread = null;
            hookThreadId = 0;
        }
    }

    public static string ForegroundExe() {
        try {
            uint pid; GetWindowThreadProcessId(GetForegroundWindow(), out pid);
            if (pid == 0) return "";
            return Process.GetProcessById((int)pid).ProcessName.ToLowerInvariant();
        } catch { return ""; }
    }

    public static void StartRecording(bool delays) {
        lock (rec) { rec.Clear(); recDown.Clear(); }
        RecordDelays = delays;
        recLast = 0;
        recSw.Restart();
        Recording = true;
    }

    public static SBStep[] StopRecording() {
        Recording = false;
        lock (rec) {
            // release anything still held so recordings stay balanced
            foreach (int vk in recDown) rec.Add(new SBStep { Type = "up", Vk = vk });
            recDown.Clear();
            return rec.ToArray();
        }
    }

    public static int RecordedCount { get { lock (rec) return rec.Count; } }

    public static void TestPlay(SBStep[] steps, int delayMs) {
        ThreadPool.QueueUserWorkItem(_ => {
            Thread.Sleep(delayMs);
            if (GameMode || ForegroundIsOwn()) return;   // never test-play into a game or into Silvan Boost
            var cts = new CancellationTokenSource();
            try { Play(steps, cts.Token); } finally { ReleaseHeld(); }
        });
    }

    // ---------------- hook thread
    static void Loop(ManualResetEvent ready) {
        MSG m;
        PeekMessage(out m, IntPtr.Zero, 0, 0, 0);   // creates this thread's message queue before anyone posts to it
        hookThreadId = GetCurrentThreadId();
        mProc = MouseCb; kProc = KeyCb;
        IntPtr mod = GetModuleHandle(null);
        mHook = SetWindowsHookEx(14, mProc, mod, 0);
        kHook = SetWindowsHookEx(13, kProc, mod, 0);
        if (mHook == IntPtr.Zero || kHook == IntPtr.Zero) LastError = "Windows refused the input hook (error " + Marshal.GetLastWin32Error() + ")";
        else LastError = "";
        ready.Set();
        while (GetMessage(out m, IntPtr.Zero, 0, 0) > 0) { TranslateMessage(ref m); DispatchMessage(ref m); }
        if (mHook != IntPtr.Zero) UnhookWindowsHookEx(mHook);
        if (kHook != IntPtr.Zero) UnhookWindowsHookEx(kHook);
        mHook = IntPtr.Zero; kHook = IntPtr.Zero;
    }

    static bool ForegroundIsOwn() {
        uint pid; GetWindowThreadProcessId(GetForegroundWindow(), out pid);
        return pid == ownPid;
    }

    static IntPtr MouseCb(int code, IntPtr w, IntPtr l) {
        try {
            if (code >= 0) {
                var s = (MSLL)Marshal.PtrToStructure(l, typeof(MSLL));
                bool injected = (s.flags & 0x1) != 0;
                int msg = (int)w;
                if (!injected) {
                    if (Recording) RecordMouse(msg, s.mouseData);
                    else if (Enabled) {
                        string trig = null; bool down = false;
                        if (msg == 0x207) { trig = "MOUSE_MIDDLE"; down = true; }
                        else if (msg == 0x208) { trig = "MOUSE_MIDDLE"; }
                        else if (msg == 0x20B || msg == 0x20C) {
                            int x = (int)(s.mouseData >> 16);
                            trig = x == 1 ? "MOUSE_BACK" : "MOUSE_FORWARD";
                            down = msg == 0x20B;
                        }
                        if (trig != null) {
                            SBBinding b;
                            if (map.TryGetValue(trig, out b) && Dispatch(b, down)) return (IntPtr)1;
                        }
                    }
                }
            }
        } catch (Exception ex) { LastError = ex.Message; }
        return CallNextHookEx(IntPtr.Zero, code, w, l);
    }

    static bool IsModifier(int vk) {
        return vk == 0x10 || vk == 0x11 || vk == 0x12 || vk == 0xA0 || vk == 0xA1 || vk == 0xA2 || vk == 0xA3 || vk == 0xA4 || vk == 0xA5 || vk == 0x5B || vk == 0x5C;
    }

    static bool Held(int vk) { return (GetAsyncKeyState(vk) & 0x8000) != 0; }

    public static string ComboName(int vk, bool ctrl, bool alt, bool shift, bool win) {
        var mods = new List<string>();
        if (ctrl) mods.Add("CTRL"); if (alt) mods.Add("ALT"); if (shift) mods.Add("SHIFT"); if (win) mods.Add("WIN");
        return "KEY:" + string.Join("+", mods.ToArray()) + ":" + vk;
    }

    static IntPtr KeyCb(int code, IntPtr w, IntPtr l) {
        try {
            if (code >= 0) {
                var s = (KBDLL)Marshal.PtrToStructure(l, typeof(KBDLL));
                bool injected = (s.flags & 0x10) != 0;
                int msg = (int)w;
                bool down = msg == 0x100 || msg == 0x104;
                int vk = (int)s.vk;
                if (!injected) {
                    if (Recording) {
                        // keys are recorded everywhere; inside Silvan Boost they are swallowed so they cannot press our own buttons
                        bool own = ForegroundIsOwn();
                        RecordKey(vk, down, own);
                        if (own) return (IntPtr)1;
                    }
                    else if (Enabled && !IsModifier(vk)) {
                        SBBinding b;
                        if (down) {
                            string held;
                            if (keyTrig.TryGetValue(vk, out held)) {
                                // auto-repeat of a key that is already bound
                                if (map.TryGetValue(held, out b)) {
                                    if (b.Kind == "remap" && Dispatch(b, true)) return (IntPtr)1;
                                    if (b.Kind != "remap") return (IntPtr)1;
                                }
                            } else {
                                string trig = ComboName(vk, Held(0x11), Held(0x12), Held(0x10), Held(0x5B) || Held(0x5C));
                                if (map.TryGetValue(trig, out b)) {
                                    if (Dispatch(b, true)) { keyTrig[vk] = trig; return (IntPtr)1; }
                                }
                            }
                        } else {
                            string held;
                            if (keyTrig.TryGetValue(vk, out held)) {
                                keyTrig.Remove(vk);
                                if (map.TryGetValue(held, out b)) { Dispatch(b, false); return (IntPtr)1; }
                            }
                        }
                    }
                }
            }
        } catch (Exception ex) { LastError = ex.Message; }
        return CallNextHookEx(IntPtr.Zero, code, w, l);
    }

    // returns true when the original input must be swallowed
    static bool Dispatch(SBBinding b, bool down) {
        if (down) {
            if (ForegroundIsOwn()) return false;                 // never fire inside Silvan Boost itself
            if (GameMode && !b.IsSimple) return false;            // anti-cheat safety: only 1:1 actions in games
            if (pressed.Contains(b.Trigger) && b.Kind != "remap") return true;
            pressed.Add(b.Trigger);
            Fired++;
        } else {
            if (!pressed.Contains(b.Trigger)) return false;
            pressed.Remove(b.Trigger);
        }
        switch (b.Kind) {
            case "disable": return true;
            case "remap": SendVk(b.Vk, down); return true;
            case "sniper": if (down) SniperOn(b.Speed); else RestoreSniper(); return true;
            case "combo":
                if (down && b.Vks != null) {
                    var vks = (int[])b.Vks.Clone();
                    ThreadPool.QueueUserWorkItem(_ => { foreach (int v in vks) SendVk(v, true); for (int i = vks.Length - 1; i >= 0; i--) SendVk(vks[i], false); });
                }
                return true;
            case "text":
                if (down && !string.IsNullOrEmpty(b.Text)) { string t = b.Text; ThreadPool.QueueUserWorkItem(_ => SendText(t)); }
                return true;
            case "media":
                if (down) { int v = MediaVk(b.Media); if (v > 0) { SendVk(v, true); SendVk(v, false); } }
                return true;
            case "run":
                if (down && !string.IsNullOrEmpty(b.Path)) {
                    string p = b.Path;
                    // explorer.exe starts the target with normal (non-admin) rights
                    ThreadPool.QueueUserWorkItem(_ => { try { Process.Start("explorer.exe", "\"" + p + "\""); } catch (Exception ex) { LastError = ex.Message; } });
                }
                return true;
            case "macro": MacroTrigger(b, down); return true;
        }
        return false;
    }

    static int MediaVk(string m) {
        switch ((m ?? "").ToLowerInvariant()) {
            case "playpause": return 0xB3; case "next": return 0xB0; case "prev": return 0xB1; case "stop": return 0xB2;
            case "volup": return 0xAF; case "voldown": return 0xAE; case "mute": return 0xAD;
        }
        return 0;
    }

    // ---------------- macros
    static void MacroTrigger(SBBinding b, bool down) {
        string id = b.Trigger;
        bool isRunning; lock (running) isRunning = running.ContainsKey(id);
        if (b.Repeat == "held") { if (down) { if (!isRunning) StartMacro(b, true); } else Cancel(id); }
        else if (b.Repeat == "toggle") { if (down) { if (isRunning) Cancel(id); else StartMacro(b, true); } }
        else { if (down && !isRunning) StartMacro(b, false); }
    }

    static void StartMacro(SBBinding b, bool loop) {
        if (b.Steps == null || b.Steps.Length == 0) return;
        var cts = new CancellationTokenSource();
        lock (running) running[b.Trigger] = cts;
        var steps = b.Steps; string id = b.Trigger;
        ThreadPool.QueueUserWorkItem(_ => {
            try {
                do {
                    int total = Play(steps, cts.Token);
                    if (loop && total < 10) cts.Token.WaitHandle.WaitOne(10);   // never spin the CPU
                } while (loop && !cts.IsCancellationRequested && !GameMode);
            } finally {
                lock (running) { CancellationTokenSource cur; if (running.TryGetValue(id, out cur) && cur == cts) running.Remove(id); }
                ReleaseHeld();
            }
        });
    }

    static int Play(SBStep[] steps, CancellationToken tok) {
        int waited = 0;
        foreach (var s in steps) {
            if (tok.IsCancellationRequested) break;
            switch (s.Type) {
                case "down": SendVk(s.Vk, true); lock (macroHeld) macroHeld.Add(s.Vk); break;
                case "up": SendVk(s.Vk, false); lock (macroHeld) macroHeld.Remove(s.Vk); break;
                case "press": SendVk(s.Vk, true); SendVk(s.Vk, false); break;
                case "mdown": SendVk(ButtonVk(s.Button), true); lock (macroHeld) macroHeld.Add(ButtonVk(s.Button)); break;
                case "mup": SendVk(ButtonVk(s.Button), false); lock (macroHeld) macroHeld.Remove(ButtonVk(s.Button)); break;
                case "click": SendVk(ButtonVk(s.Button), true); SendVk(ButtonVk(s.Button), false); break;
                case "text": SendText(s.Text); break;
                case "delay": int ms = Math.Max(0, Math.Min(60000, s.Ms)); waited += ms; if (tok.WaitHandle.WaitOne(ms)) return waited; break;
            }
        }
        return waited;
    }

    static int ButtonVk(int button) {
        switch (button) { case 1: return 0x01; case 2: return 0x02; case 3: return 0x04; case 4: return 0x05; case 5: return 0x06; }
        return 0x01;
    }

    static void ReleaseHeld() {
        int[] keys; lock (macroHeld) { keys = new int[macroHeld.Count]; macroHeld.CopyTo(keys); macroHeld.Clear(); }
        foreach (int vk in keys) SendVk(vk, false);
    }

    static void Cancel(string id) {
        CancellationTokenSource c = null;
        lock (running) { if (running.TryGetValue(id, out c)) running.Remove(id); }
        if (c != null) c.Cancel();
    }

    static void CancelAll() {
        List<CancellationTokenSource> all;
        lock (running) { all = new List<CancellationTokenSource>(running.Values); running.Clear(); }
        foreach (var c in all) c.Cancel();
        pressed.Clear();
        keyTrig.Clear();
        RestoreSniper();
    }

    // ---------------- recording
    static void AddRec(SBStep s, bool allowOwn) {
        if (!allowOwn && ForegroundIsOwn()) return;   // clicks on our own Stop button are not part of the macro
        lock (rec) {
            long t = recSw.ElapsedMilliseconds;
            if (rec.Count > 0) {
                int d = RecordDelays ? (int)(t - recLast) : 10;
                if (d > 0) rec.Add(new SBStep { Type = "delay", Ms = Math.Min(d, 60000) });
            }
            recLast = t;
            rec.Add(s);
        }
    }

    static void RecordKey(int vk, bool down, bool own) {
        if (down) { lock (rec) { if (recDown.Contains(vk)) return; recDown.Add(vk); } AddRec(new SBStep { Type = "down", Vk = vk }, true); }
        else { lock (rec) { if (!recDown.Contains(vk)) return; recDown.Remove(vk); } AddRec(new SBStep { Type = "up", Vk = vk }, true); }
    }

    static void RecordMouse(int msg, uint data) {
        int btn = 0; bool down = false;
        switch (msg) {
            case 0x201: btn = 1; down = true; break; case 0x202: btn = 1; break;
            case 0x204: btn = 2; down = true; break; case 0x205: btn = 2; break;
            case 0x207: btn = 3; down = true; break; case 0x208: btn = 3; break;
            case 0x20B: btn = (int)(data >> 16) == 1 ? 4 : 5; down = true; break;
            case 0x20C: btn = (int)(data >> 16) == 1 ? 4 : 5; break;
        }
        if (btn == 0) return;
        AddRec(new SBStep { Type = down ? "mdown" : "mup", Button = btn }, false);
    }

    // ---------------- output
    static bool IsExtended(int vk) {
        return (vk >= 0x21 && vk <= 0x28) || vk == 0x2D || vk == 0x2E || vk == 0x5B || vk == 0x5C || vk == 0x5D || vk == 0x6F || vk == 0x90 || vk == 0xA3 || vk == 0xA5;
    }

    public static void SendVk(int vk, bool down) {
        var inp = new INPUT[1];
        if (vk >= 1 && vk <= 6 && vk != 3) {
            uint f = 0, data = 0;
            switch (vk) {
                case 1: f = down ? 0x2u : 0x4u; break;
                case 2: f = down ? 0x8u : 0x10u; break;
                case 4: f = down ? 0x20u : 0x40u; break;
                case 5: f = down ? 0x80u : 0x100u; data = 1; break;
                case 6: f = down ? 0x80u : 0x100u; data = 2; break;
            }
            inp[0].type = 0;
            inp[0].u.mi = new MOUSEINPUT { flags = f, mouseData = data };
        } else {
            uint scan = MapVirtualKey((uint)vk, 0);
            uint f = down ? 0u : 0x2u;
            inp[0].type = 1;
            if (scan != 0 && !(vk >= 0xA6 && vk <= 0xB7)) {
                f |= 0x8u;
                if (IsExtended(vk)) f |= 0x1u;
                inp[0].u.ki = new KEYBDINPUT { vk = 0, scan = (ushort)scan, flags = f };
            } else {
                if (vk >= 0xA6 && vk <= 0xB7) f |= 0x1u;
                inp[0].u.ki = new KEYBDINPUT { vk = (ushort)vk, scan = 0, flags = f };
            }
        }
        SendInput(1, inp, Marshal.SizeOf(typeof(INPUT)));
    }

    public static void SendText(string text) {
        if (string.IsNullOrEmpty(text)) return;
        foreach (char c in text.Replace("\r\n", "\n")) {
            if (c == '\n') { SendVk(0x0D, true); SendVk(0x0D, false); continue; }
            var inp = new INPUT[2];
            inp[0].type = 1; inp[0].u.ki = new KEYBDINPUT { scan = c, flags = 0x4 };
            inp[1].type = 1; inp[1].u.ki = new KEYBDINPUT { scan = c, flags = 0x4 | 0x2 };
            SendInput(2, inp, Marshal.SizeOf(typeof(INPUT)));
        }
    }

    // ---------------- sniper (temporary pointer speed, never saved to the user profile)
    static void SniperOn(int speed) {
        if (savedSpeed < 0) { int cur = 10; if (SystemParametersInfo(0x70, 0, ref cur, 0)) savedSpeed = cur; else savedSpeed = 10; }
        SystemParametersInfoSet(0x71, 0, (IntPtr)Math.Max(1, Math.Min(20, speed)), 0);
    }

    public static void RestoreSniper() {
        if (savedSpeed >= 0) { SystemParametersInfoSet(0x71, 0, (IntPtr)savedSpeed, 0); savedSpeed = -1; }
    }
}

public static class SBKeyName {
    [DllImport("user32.dll")] static extern uint MapVirtualKey(uint code, uint type);
    // character printed on the key in the current keyboard layout (0 if none)
    public static int Char(int vk) { return (int)(MapVirtualKey((uint)vk, 2) & 0x7FFF); }
}
'@

Add-Type -ReferencedAssemblies @([System.Windows.Window].Assembly.Location, [System.Windows.UIElement].Assembly.Location, [System.Windows.DependencyObject].Assembly.Location, [System.Xaml.XamlReader].Assembly.Location) -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;

// Runtime UI translation: walks the window and swaps known English texts for German (and back).
public static class SBLang {
    public static string Lang = "en";
    static readonly Dictionary<string, string> de = new Dictionary<string, string>(StringComparer.Ordinal);
    static readonly Dictionary<string, string> rev = new Dictionary<string, string>(StringComparer.Ordinal);
    static readonly List<KeyValuePair<Regex, string>> pats = new List<KeyValuePair<Regex, string>>();

    public static int Count { get { return de.Count; } }

    public static void Add(string en, string ger) {
        if (string.IsNullOrEmpty(en) || ger == null) return;
        de[en] = ger;
        if (!rev.ContainsKey(ger)) rev[ger] = en;
    }

    public static void AddPattern(string rx, string rep) {
        pats.Add(new KeyValuePair<Regex, string>(new Regex(rx, RegexOptions.Compiled | RegexOptions.Singleline), rep));
    }

    static string ToDe(string s) {
        string r;
        if (de.TryGetValue(s, out r)) return r;
        if (s.Length > 400) return null;
        foreach (var p in pats) {
            if (p.Key.IsMatch(s)) {
                r = p.Key.Replace(s, p.Value);
                if (r != s) { if (!rev.ContainsKey(r)) rev[r] = s; return r; }
            }
        }
        return null;
    }

    // translate one string for the current language (used for messages, status texts and new UI)
    public static string Tr(string s) {
        if (string.IsNullOrEmpty(s)) return s;
        string r;
        if (Lang == "de") { r = ToDe(s); return r ?? s; }
        if (rev.TryGetValue(s, out r)) return r;
        return s;
    }

    static string Map(string s, bool toDe) {
        if (string.IsNullOrEmpty(s)) return null;
        if (toDe) return ToDe(s);
        string r;
        return rev.TryGetValue(s, out r) ? r : null;
    }

    public static int Apply(DependencyObject root) {
        if (root == null) return 0;
        int n = 0;
        Walk(root, Lang == "de", ref n, 0);
        return n;
    }

    static void Walk(DependencyObject d, bool toDe, ref int n, int depth) {
        if (depth > 200) return;
        string r;
        var tb = d as TextBlock;
        if (tb != null) {
            if (tb.Inlines.Count <= 1) { r = Map(tb.Text, toDe); if (r != null) { tb.Text = r; n++; } }
        } else {
            var cc = d as ContentControl;
            if (cc != null) {
                var s = cc.Content as string;
                if (s != null) { r = Map(s, toDe); if (r != null) { cc.Content = r; n++; } }
            }
            var hc = d as HeaderedItemsControl;
            if (hc != null) {
                var s = hc.Header as string;
                if (s != null) { r = Map(s, toDe); if (r != null) { hc.Header = r; n++; } }
            }
            var tx = d as TextBox;
            if (tx != null) {
                var s = tx.Tag as string;
                if (s != null) { r = Map(s, toDe); if (r != null) { tx.Tag = r; n++; } }
            }
        }
        var fe = d as FrameworkElement;
        if (fe != null) {
            var tt = fe.ToolTip as string;
            if (tt != null) { r = Map(tt, toDe); if (r != null) { fe.ToolTip = r; n++; } }
        }
        foreach (object c in LogicalTreeHelper.GetChildren(d)) {
            var cd = c as DependencyObject;
            if (cd != null) Walk(cd, toDe, ref n, depth + 1);
        }
    }
}
'@

try { [void][SBNative]::ShowWindow([SBNative]::GetConsoleWindow(), 0) } catch { }
try { Get-ChildItem -LiteralPath $PSScriptRoot -File | Unblock-File -ErrorAction SilentlyContinue } catch { }

# ------------------------------------------------------------------ taskbar identity + logo
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SBShell {
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] public static extern int SetCurrentProcessExplicitAppUserModelID(string id);
}
'@
try { [void][SBShell]::SetCurrentProcessExplicitAppUserModelID('Silvan.SilvanBoost') } catch { }
$script:LogoPng = [Convert]::FromBase64String((@'
iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAA2O0lEQVR4nO2deZQkV3nlf+9FblXV3dWLurrVaqml1oZWhBiBhBBaLAkZLLYZMYBtLNkGbI5t
xoDHxuYYM2MGYYFlzoxZ5IEBDMgWGINkA1qwBEiW2gIJtKO9V3VXq/euJZd43/wRGVWZWRlbZkZkVtW752R3Vrx3v4jKyu/et0S8BxYWFhYWFhYWFhYWFhYW
FhYWFhYWFhYWFhYWFgsMqt8X0E/ITZeOUp3W/b6ObHAg1erzFqPAtx8+qL6B2+9L6QcWvADMJHneKYK5GqHkFUgRuBqlioi0IfpvTMDxgAMSWLElXBAvYdzY
vPBqsSsG8YLogeVp8Ux4eevf2lHgsgkxmwAoaCjLfWhnE6NA/uGD6q0LVxwWnADITZeOQnUIzNWgRjHmarQqYkRTckZR9V/ZAFVD4gTuOhH7lfgRCTXwPB9+
grd+dbsQFK3AaTg0ZQzIAXIKXNlEgU2U1X2scDYttNbCghCAetKfR15dSNW9GqWGyGsv2SsNfysj3hdAESOxOhUAKxzp8GLG7QVPgWcUAhqvlTBtDA4HMGxC
5IeM6C/x3cd2z3cxmLcCMCfpUWOUHE3FeH9MYwKIc97EK19wwtByoO+8mHEz4/nF9QI/U3LKE4eaOYAr9yL8kKXzVwzmlQDIVVc5/Mb4aib4HbS8B6Eh6evu
bhO8S17Lgb7zYsbNWhiQBjGQA2juxXU/zeHavepPnp03Q6jzQgDkqqscfm38Mox+H0bOw1GjuGa2Sd9UOWEiRpUvOGFoOdB3Xsy4/XL+ODyFJwY1MRgZR/g8
+eJn1HsfGg86+6BgoAVAbrrKwRm/DK3fh5HLcZSmVk/8OZXnvIlXvuAS3ApDOjy/OOjvLbNjBzmgYsYR9dlBF4KBFQD5p/PGcAs3kFdXotVs3z4w4azzJyrv
Oy9m3EFJ8KQ8XReCmoxj5D38+MlbBnGMYOAEQP7pvDFM4b3A75LXY1SjEn/Om3jlCy7BrTCkw/OLOxQGDYi4aHU7Ip9m7MnbB+m+goERALnpKgc9fiWO+jyO
HqNmwJUYCWeFIVF533kx486XBI/D88cIRAxVuYWC+2713mcHolswEAIgn3/5MKuWfB1H/QqCM5P4CpvgqfFaDvSdFzPufBYGRb1FwDg1913qD5+5OeiqskLf
BUD+4aLXUuL9aH05FXf2A7XO3yWv5UDfeTHjzucEj8vzZgwmUVxH5eB16o92TQTUTh19E4CZJr9WXyOnhym3dItsgqfEaznQd17MuAtNGBRQ0jBpbqHo/na/
ugR9EQD5ymUjDFe+hqN+BYPTNK1nnb9LXsuBvvNixl1oCR6X5wDCOK7pS5cg80dh5fMvH2aociNF54244syd0xfafooBh6NP6PMSBuial7Biz3gxA2XGq5cn
/vulxYsImDWvJqAYw9E3yvXHvyG4YjrItAXQ1N+f0+Sf86al3Dp/ovK+82LGXazO31ruKHBlEuQ6aoczGxfITADkpte8gZxzIzk1t78PNsFT47Uc6DsvZtzF
KAz+uMCUewu1w2/PQgQyEQAv+fWNwDBu0oSzwpCovO+8mHEXY4LHKReBooaKyUQEUheA0OQHm+Cp8VoO9J0XM64VBu//jEQg1UFAuemCS8iHOH/oZxFQYeZw
ZICMeS3lsU/TKS88TOxAPePFJGTGa6YnKEiJFwGRZnEoGyjoK9EjX5OPpJenqQWWr1w2gtIfxtHtnT8ywZOe0OdlLQwJK/aMl3WCxxTAgRGGrBM8iteS4HFQ
MeCoKxnekNrsQCoCIF+5bKQ+1Xdx29F+6/xd8MLDWOdvpicoSIkXgTBhEEBEU8p9VT55bCoi0HMBkI+gKVW+Rsm5su1ov3X+LnnW+Re88zfyDCAyQs65Ua7b
eEnyQOHofQvglAvfQF7NTX7r/F3ywsNY52+mJyhIiReBJMLgAg7DOPJhuW7NSAdnC0RPBUBuuuASiuqrGPTcD8U6f3c86/yLyvlbURHI64thuKeDgj0L1DDo
NzLn3n7r/F3wwsNY52+mJyhIiReBboShYiDX20HBngjATL+/3aCfdf4uedb5F7Xzzzm1aIrOV3s1HtCbFsAZF76BnLqyaRMO6/xd8sLDWOdvpicoSIkXgV4J
gwE0Iyj5sFy7cbSDK2lC1wIgXzlvDPgCtPb7rfN3x7POb50/ABWBkr4Y3PcnP2Ezum8BDBXeS8FZOXOzj3X+LnnhYazzN9MTFKTEi0BawlB2IcfvyHUbxzq4
qhl0JQBy07krUfzu7Mq9YJ2/W551fuv8Ybz6ywB5PYaY300eZBYdC4DcdJUDhS+Q02Mzo/7W+bvghYexzt9MT1CQEi8CqQlDwwXVBPL8oVx3TMcDgp23APT4
xeT1G6hKeEJZ54/Js85vnT+M1+ZyDKDVKKL/VG5q2uA8NjoSALnpKgeRP0YrHf3LWOdPhL4LQ0yCdf4AXgbO34iKAYeLeP6Yi5OftNMWgBm/mJy+mIoJvjDr
/DF51vmt84fxwi8HATQOov64k1ZAYgGQ715RRPMnKOWE/6Gt8ydC34UhJsE6fwAvY+dvPFwTcLiY5zdclvT0yVsAh6dWoDiXmu/+IReWBNb5Y4Wxzh9VvEic
v7GCADnlgFya9DSJBEAEhfA75PVw2y26Wy+s7WHr/GFhrPM30xMUpMSLQD+dvxE1Afg1+dhxa5JcRrIWwN+fOYwy78E1c9cStM4fk2ed3zp/GC/8cgIruAJ5
vQbH/fUkp0smAIXRV+PoFe3d3zp/IvRdGGISrPMH8AbE+RthDCgulU+fUIx7ObEFQAQFXE5eF5suxDp/TJ51fuv8Ybzwy4klDAaAV3OosjLuaeO3AP7+zGGU
ers39Zfkwqzzh4Wxzt9MT1CQEi8CA+f8DRUMkFfD5NU74l5WfAEojL6anFo580tY54/Js85vnT+MF345iYVBUCCXxe0GxBKApub/TAPAOn8i9F0YYhKs8wfw
Btj5G+EKSPxuQLwWwA0vX4ZuaP5b54/Bs85vnT+MF345HQuDEcgzjMM741xGLk4lhoeHUQzPJmIbyJw38ZA6T0J/7D0vPEzsQD3jxSRkxmumJyhIiReBTpI7
Fi8qj7rgKRTIShGUUuER47UACuqd5PWy4Jt/QmCdP1YY6/xRxdb5Y/NqAkp+nU9sXBZ1OZEC4PX/ZWVdVULOm3WCx/ziB/zYe154mOyFISYhM14zPUFBSrwI
zJc+fxBPMUytNhwWEeK0AL504SjCO+dO/0XAOn+sMNb5o4qt8yfmGcDRy0CujrqseGMASkpzdhKXOW/iIXWehP7Ye154mNiBesaLSciM10xPUJASLwLzsc/f
DkoUykROBUYLwAilRB9m34QhYcWe8bJO8BhfNNVQrVG3W4/PaVGElUdc4MAkeBQvrQQP4nVYoRc8RxWjBgKjBcCYayjlRmc2/LDOHytM6sLgQwNagaonvlHg
CsZAzYBrBCPe/wJQX79VAUrVX4BC0BocpXA0OMqPXX+ZuiL4Lc7GV6LfL+bvaZ2/O14NMHI1f7HhE7B5f1DtaAHQlFComW9NxHmt80dV65CnZDbZBUxFmKwI
uw8bNu81bN3vsuuQYddBYc+kYd+UcGBKmKgIU1VhquoLAhgRHAU5rcg5kNPeq5RXLC0oRoqKJUVYUlAsLSpWDsOqEc0Rw4pVI4pVw4o1SxUjBSg6ilwOyNW/
HLM72ob/qtb50+cpSpQkLGvjtADU7OifhFxAEKzzJ+PN2HP95SgwwuSU8Owew4Pbajy6o8YTuw1Pjru8eNhQrgnTNah4z4SjVL1RoNSM08Nc/ZbGi2g0d/HK
Gse7co4iryHveO9LOVg9ojhqVHPUqGLdMu//Y1dojl+lWT0CQ3lFLj/7O/RHGCKw0Jy/9eC0CmWGCoAIin+MGAOwzh8rTGyeBhyFVIWte11+9EyVe56tct/z
NbbsMxwuC5WaeM10rdD1rHY0DBdCxT4hmmP52l9xoeIKE2XYfVh4ZKfBiCcWOUcxlPNaEkeMKDauVGxcqdm4SvOSMc0pY5rVI4rhApCvdylcZlUnDNb5O+Ep
RiiFVQhvAXzpwlFK7tVUos8UfGHW+SN5Cs+yEXbsNdz6WIVbHq2w6fkqL04IVVfI6XrfvOeJHg+q/o9qOOA0lyJ43YxDZeHAtPDkbnClhsLrLgwXFEePKk4Z
8wTh1DWalx6pOXKZZiiPF7BxnVlfGGJ1PRNiYTu/J6x5PUq5dg3w8SB2uAAUXIWi1PYk1vljhQnl1Zv4pibc+1SFr/+kzL8+WmH7AYMxQt7xkj6ns0/4TtAo
Elp54wp+9roGDk4LD00KD2w3CMJQfczhuJWKs9Z5YnDWOoeXrFasGFKQxxMEl+BZiyAsbuf3oFDobloA8U/VprZ1/tBqOTBV4bbHKnzu7mnufLLCobJQcBR5
B5QzP5I+LvzZBu144wigEIGDZeGB7cJ/bDVoBSNFGBtRnH2U5hXrHV5xtOaMNYrlw6o+G1EPaJ0/4vDMmFLnYwCxTpAZL2HFQXX+erv57icrfOoHU9z2RIXp
mpf4Q/mFlfRRmCsKUKnBlv3Cs3tdvvmwy0gB1izxBOFDF+Y5a72aFYF2sM6fCMkFIAjW+cN5Csgptu2pcd3tk3x50zSHpoViTlHKLa7ED4NWjd0HqLqweb/w
9Isurz/Z4axjHK9LkBSLzfljIr4AWOePFaYtr/5l/vZPp/mzf5ng8Z01L/EXmeN3Al2/WUnnZkWhLazzd4TuWwDW+cN5DhyeFv7Hdyf42x9NUXVZdE39vsI6
fyiiBUD82Nb5Y/P8tznY/KLh9/7hIN99rEIhp2b6uhY9gnX+YJ5A+IBJNy0A6/zhvLzikS1VrvnqQX66tWZdP2tY54+FGAJgSLR/iHV+yCsefK7Kr375IL/Y
ZZM/FVjnj+DFCzCA04Dz3Plzike3VHnHlw7w1G5jB/qyhnX+RBigacCEFQfJ+X04sO1Fl2u+eognd7t2ei8NRD1MFMbr6HwdVhhw5/cxQNOA89z5NUyWhd//
xiHu31pl2Dp/bxH1cVrnb4+IlfwGYBowYcVBdH4Arbj21glufqRs+/xpodM1/Do6V4cV5onz+xiAacB57vwAOcXtj5b59F2T5B0VaVYWPYR1/mBeDEofpwET
VhxY54f9hwwfvmWCiYp3a6/FAMA6fyzEEICYUtJYvflNVMV41bvmhYfpWBg0fOZHk/xkS9WO+GcJ6/w94fVhGjBhxUF1fgANz+2q8bl7psktsMd35y2s8ydC
H6YBF4jzI6AVn7t7mm37XTvwlxVSmwZcXM7vI8NpwIQVB9n5AbRi6+4a//hAmYJ1//7DOn9HyHAacAE5P4BW/MMDFbbucwe67+8bpkh9Yd6ZnyU8Z+orCs88
jtu0h8DsSsOZwf8lEvOs84chg2nAhBUH3fkBFExNCv/0szI6wWMSWcBP9Gp9/f+hnGI4D0uKitUjirElmlXD3s9Lit7y3v66gyJQM0LFhYmycLgi7JuCfZPC
rsPC/imh7ArTVZiqeufzNxFp3GQk81+4I16HFeaL88/kbd+fBlxgzi9ATrFpc4VHX6iRH5AFO13jLdddyimOXKY4+yiHs45yOHWN5oQjNEePakp5KNQ3AsHf
+ce3dD91pb51kPFexnir8lSMcGgadhwwbN5v2LxPeGaP4RcvGp7ZI+ybEiYq3qrA+frqxX0RBB/W+WMhxWnAhBXng/M3VL318QoTFen74J9rPLdfu1Tx2pPz
XHlajvOPzbF6RKH8tfebltqu/571BJ+FNP0HgAKtoaihCCwtwrrlmv90rPbEw4VK1Vvw5Mndhod3GX7+guGB7Yan9xgOTHv7CPiC0FOttM7fE16K04ALzPl9
KJieMtz5VDV8iaoMMF3zFsy8+pwCv3lugRNWa28LMX+zjWqb3znwY4ioG8AraGHlCJy7RHPu8RoMTJdh2wHDpq2GTVsM92x2eWavcKjstQjyToqtA+v8iZDC
NGDCivPF+f1qjuLpF2s8tdvF6VPzX/BWz738pBwff33JWyhTBFxJluCximPw/Cr1xTpLeThhteKENQ6/erbD5HSeR8cNP3rWcMczLg/sMOyd9C457yRsGXQ8
DdhhhQXq/D5SmAZcoM7vw4H7t9Q4NG36cvOP4PXJf+uVBT75xhJLh5S3E6zQ4Q46KQiDP4ZQF4ThApxzjOacYzXvO9/hub3CD542/OuTLpu2GvZMzq4E3LGm
Wudvj+yeBkxYcb45vw8jPLy9RtWlL+v7VWrwtpfl+fRbhijlgFrDBbb9lVJ0/rgFgicGrpfkJ65WnLjW4V2vcHh6j/CvT7h8+3HDz14wHC57n6ujW/SsY2Ho
sMICd34fMXYHpv7hL3LnB1BQqxge3eni9MH9qy6cusbhk1cOUcoTb338fnQJosrrLQRHw8lrFCcfmeP3zhU2bTP80yOGf/mFYfN+b0ubgj9TERjPOn8gLwal
B9OACSvOV+evH5gow7MvuvTjoT8FvP/CImtXqtkBvoFJ8CheQMugBigo5OCC4zUXbNR86KBwy+OGrz1k+Mk2w0QFcklbW9b5Y6EH04CLwPl9aNh50LB/WjK/
E67mwsljmjefnpsd5R+UPn+M4lCiz615/61Zqvjtcx3e+TKHHz3v8qUHDN990uA29met8/eE18U0YMKK89z5AVCKHQcM5ZpkfoNL1QiXnJhjdInyRvtbLm0W
88D5o2AAVyg4cOlJmkuP1/xsh3hbiEd1e6zzJ0IXg4CLyPkbqu08ZKi62d4LL0BeK15+lOPdgFOLqJysICVeBOIIg99FAG9TUGFW/JJekHX+tuhgGjBhxYXg
/D6Ud1981YVi7+6giIQIDBXguFXau9G/fa2IIIkLuuR1qAxBPOv8XZ64PTr4Gi9O5/dxaNrgmqgOeO+R04rlQyr4sheS83fEs87fCRI8DRj7Str+2DlvAJy/
AZPVeGF7Da28e+rnYoE7fySvwwoL3flj5m2CFsDidn4AjFCJ7IOmA9cIE5U257bOn+hw+rxBc/7wWwF78DhLi9QkajGE8WIGyoznldcibq1MAwrvwZ+t+6Xh
LxZxvYHFafGksyTvmBd+OYEVUuNFhUsYoGtePMQQgLQSPCb6LgyNUPRjd2+lYKoqPLi9Yfg/8wQPLw7mpSUMWSd4FC/rBI9nWFHoogWwuJzfr9KP+/8BHK34
3hM1JieN98hvEKzzt69gnb8t4gvAonb+OhR92/Mv78DPdxi+/XAtYOTGOr91/jblEV3WDloAi9D5G6otLSl05itieuMARuBjPyizedzMFQHr/O0rWOcPRbQA
WOdvqnvEiCLvdPWZd4y8A7/YbXj3N6bZdUDqIhCRUNb5U+INuPPHPE2CFsDidn6vSFizVFHIxTt1GijmFHc87fJfvjzFg1tcTwQC7w+wzt97XlS4+eH8Pvo4
DRgeZqCc3yeIcMxyh2JO9Sv/ASjl4N7NLq//whQfu7XCzoMCecBh9gZF6/wp8RaG8/vo4zTgPHJ+H8Z7VPWIERV8S35GKOZg76Tw57dVuOhzU/zP71d4YqdB
RCAns0t+t8I6f4e8qHCD5vzxKvbhacDwMLED9YwXk1D/b7igeMmYw1O7XXJ93hPAqS+3/dxew1/cXuH/3FPhNRsdXv+SHBcf77B+VOEU6tceumAoXfz9OiTa
O/y65PUm//rwNGDWCR7zg4wTXkAXFGesc/j2I/EuJwvktPc6WIZvPeLynUddjhhRvOwozQXHOrzyaM2Za72HiZxCneTvCxCViPbe/ghe1sLQs4pApk8DhocZ
dOdvPH7O+hxD9XGAwdgXyINW3viAAHunhFt/4fK9J1yWFLzZizPWal56pOb0tZrT1yiOWa4YyYPK1wM0bhYS2WOyzt8fXo/yr44Mnwacx87fCFc4Z4Nm9RLF
rkOCM2B7A4InSo4Cp/7XrRnYcVDYst/l5sddSjkYKXibipw2pjl1jeLUMc3pa7QnCgVQuYbxkFZR6GqRziBehxWs87evGDNvM3gaMDzM/HH+OgyMLdWcd2yO
b/ys0rfNQZJAqbog1MVKBCYq8PQe4YndLt94hLmiMKY4dY3i9LEGUchT32K4HjjJZ2udv0tep/mX1uagM1gkzt/A03nF60/J862HKkmDDAT8bbn8zTggniic
NqY4bQ2cuVazfpliuIg39Vhfw68jWOeP4CWsmPA0yVcFXqzO3whXeO3JOTascNiy3/R9j8BeIK4oDNVF4ZjlirPXaV52pOKcozSnrIYlJbxvlL9qsWCdv2te
pwker2KK04ALz/lnYGBsheZNZ+T51F3TfZ8OTAtBonC4Ag/vEh7c4aIVLCnC0csUrzxacf4xivM3aI5bocgXaJhtaAlunT+Cl7Bih79fCtOAUbx57PxNNOHq
cwp8+f4yB6cZyMHANNAoCv4SZeUaPLlHeHRc+MqDsHzI5aVrFb+0UXPp8Yoz1ygKRWYHFAWyT/BF6vzZPw0450CsMOnx6uUxw8fmuXDaOof/elahb8uEDQr8
FsJQ3tvB51AZ7nxW+NM7XC77Uo3Lvlzjr+4yPL5TECPNtyzPQcAHHvn365QXFS5hgK55CSt2+vvV0cOnAaN4WQtDTEI3PIQ/uKDI+uW6L0uFDSL81kEx540X
TNfg37cIH7rd5cIv1rjqH12++ZDhUJnmB5lSS/AoXtYJHtOwAn7sNa+HTwMuEudvhAsnrtX8twuKuKYrIV6w0AoKjjejcKgM//y48GvfdLnoiy7X/9iww3+s
WVvnT1SxS+f30fuea9+FISahVzwXfuf8ApeemKNc7cFfZAHDv1NRa28Q8YO3Gi76f4aP/cCw42BdCOZ0DazzxzxBQp6HCAE40BA16ASL0PmbaMJwET75hhJH
L9dU42zZvcih8BY3KeVg837hz+80XPL/hP99j3C4wuzQtHX+uRU75QWgdy2AvgtDTEIavBqcfpTD9W8sUcrTvIutRShy2hOCZ/cLf3ir4Zf/3nDHk+J1CbR1
/t7zmtHFoqCL3PkbeQCu8Oaz8vzlFSVQnd8Yt1iR195Ywb1bhbf8g+GD3xf2TtJmoto6f49OAPSiBdB3YYhJSJsngAt/8JoCH7msCGJbAkmh8GYPqgb++t+F
N94oPLBNPBGwzt8lrz06mAa0zh/IE0CED/1SgY9dUcTR2OnBDqCVd0/BvVuFN90o/PMj4q1yZJ2/57zOWwB9F4aYhMx4ddTvdPvAJQU++5YSoyVFpRbJsmiD
Yg52TsA13xG+cD+035bJOn84erY3oHX+cF5DgQAG3vnKPN96Z4kzjtRMVen4UfnFjLyGqSq87/vC/20UAev8XfI8JG8BWOcPpTf9XINXn+jwL781xG+dk0OA
ip0mTIyc9sYFPnC78M2Hmd0PwTp/fF4Akq8KHLvaInT+dqjCumWKv7uqxFfeVuKUMc10zQ4QJkVOw1QN/uBW4f7NBHQHQmCdvy3m0TRgTEK/nb9dQT3Zrzo7
x+3vHuJDFxdYOayYqtrpwiTIa9h12OsO7J2g+dtrnb99xd4/DRh+Puv8AcUCVGHNUvjL1+W5/d0l3nNujmXFuhDYFkEslHJw33b4+N3EW5HVOn8owgWgzZ3A
1vmb6QkKPLhADU5bq/nsfy5yx7tK/P75ecaWKKar3hiBHSwMRzEHf/cA3P0c3jfYOn/HvHkwDTjPnT+owPVeZx6l+fSbCvzwPSWu/eU8L1unUcob+a7ZJwzb
Qis4VIGP3wPVmkTsgGSdPwwDPA0YkzBfnD+ouCbgCsetUvzRL+W5690lvvFrRd71ihzrRxXGNIiBVYMZFHPwb8/D954CHOv8yXkekq8JOCd4zLMl5kmi8Onz
IgJ2yvOrCGBguACvO9XhdS/RjB/Icddzhtuecvnxc4btB4XJ6uyWYBpvia7FCAWUDdzwgOJ1Jwq5xk1Rm9/EQ9e8hBVT58VDzFWBY6BnwhCTkBmvmZ6goDOe
ADXv/7Fliree7fDWlzrsnYD/2Ga453mXuzcbHh83HJj2WgdOfUkupbzm8WJBUcOPt8L92xXnbRCvWxWE1IUh6wSP4sUL1MWioNb5U+c1bNW1cgSuOEVzxUsU
lbK308/92w0P7BB+tsPw2G5h35QwUfG6CjnHEwZ/Ec+FCKW8VYa++TicdwwNTfQEWKTO76P7jUGs82fDM8w4XCEHx65SHLva4aqzoFaBfZPCo+OGn78g/Hyn
8POdhi37vQU2pmoLt5WQd+DWZ+Ajk7CsxNzPzzp/KDrYG9A6f394bQZ66q2DnIbVS+GiUc1FJwE1mKzAtgPCgy8YHt4p/Gyn8Ni4Yc+kt9mHEY/n6PndSnA0
PH8A/mMHXHqieN2nOFjozj8nb9uj8xaAdf6MeBGQht+z4Wai4QKcNKY4aa3mvwq4Vdg/BY/v9loHP98p/OwF4bl9wqGKt7a/v834fBIEBUxUvbGAS09sKLDO
Hwudbw4au5p1/u54HSqDqfPq3QZHw6ol8Oqlilef4EBNmKrA1gPCT18QHtgu3LtV+MWLwv5pj57X3gKegy4GjvJaAG4FHIfwj3QxOH8Ter05qHX+jHgRSCoM
fpOwgTeUh5NWK05aq3j7S2G6DJv3GX68RbjzOW89/+2HBNd4y3UN6thBTsNjLyr2TAljS0h5MHBhOL+PPk4DWucP53X4h03CaxxLEO8++5PHFCcfqfjtl8ML
h+DfnjV85xfCXc8Ke6ZmuwmDBKXgwDQ8vU8xtjTg9190zh8vUB+eBoxJyIzXTE9QkBIvAiKdiUMkr15ugKp35Mhl8Ktna266SnPnNZo/uUBx1FLFdG22hzEI
0Aoma/DUHoI3GAnCTPUoXkt57NOkxYsZaPCeBsw6waN4WSd4FC+tBA/iBVyO3zKob3Zy2lrFxy7X3Pmbig+8SjOUH6zFTaoubDnI3N8ldoIH8RJWTJ0XHiZp
oAwXBY1JsM4fwEvR+dtdUONhYeYpxg3LFX91heLbb9OcMebt/TcIUMD2w0Q63gwWuvPHrJbh04DW+eeF80dVqAvBazbCt96mOW+9N4XYb2gNuyfAuHhqYJ0/
FjJ4GjAmwTp/AK+Pzh/Gq8Gxq+ALb9Qct8Jbs6+fUMDe6RjXYZ2/CRksCmqdf0E4f7vDNTh5LXzkQoVWnelbr6AUHK7UV1ayzh8bKS4KGpNgnT+AN6DO34oq
vPVUxavWq74OCipgquatn9AWi8754/FSnAa0zr9gnb/legol4a2nzXa9+4WaC2KdPxFSeBowJiEzXjM9QUFKvAikdgNQQHnk6WLwDFx8LCwvec3wfi1S0vYj
kDlvgtihP2bPixmoU14dKUwDWudfFM7fWMHA0ctg/bL+LnPudLQ0WMKK88X5Y1br4TRgTEJmvGZ6goKUeBGYL33+gMOlHGwYDemDZ4CcbnheYeY6YxpWwI/Z
8zpN8M6+eDG7AHGCS9N/8ZEWLyJg5rwOrbFjXocVOuGJl3jLi51pXy8gwJATw9FiX6CE/th7XniY2IHmVEv9acCYhMx4zfQEBbF5NQO5fP2QmVOcDPOxzx9Q
wenjQ0IisLTgPfY86/yhjNAfs+d1muDdSW7MacCo8iyb9lG8lJv2efjHh2r82XcrbN8v3r71OoyXVtM+4jqTVuiGV/9/ohrrClOBAMuKzK4O3K5CX5v2MZFx
l6CLacCYhMx4zfQEBcl4CnZPCP/rjioX3zDNX/2gxs4D4rWlkjjgPO/zt1aouLD9UP/WDDACRwwL2kn4+fRdGNJN8BSfBlxkzt8AR4HOKzbvFz50a5WLbihz
7Q9qbPeFwGFxOL9/WMGLk/DcPvrWDRCB1cPM/Ub3PcFjImthqKODacCYhIXm/G2Q097o93P7hD+7rcpFny/zke9XeWrceCLgMHc9rQXm/AA4cM82eHGqfy0A
R8NRSwhZv2yROX/Mah3o9eJ1/tmCZvhCsOWA8D/vrHHR31X4/e/UuH+L8RbOyBG9sN58dP46TA1uetR7Jr8f+W8ESg5sGG3YTLHvCR4TfXJ+H93fCdh0AZ1c
Q6e8ZnqCgu55AVX85bL2TAh/e2+Nr/0MLjpO886XOVx2vGZkuM41wTHmni+qYkB5ZPwe8XJw51Pe2vwFJ4qbHko52LicNn1eCf0xGGnxYgbqGS8cye8DyCzB
o3gpJngnvAY4Goa0t23Xdx43fO9Jw2ljiv9ymsObT9ecfISCPPUdgjtUvqwSPOywA3sOwYfv9DYf6ZcAGIE1I3D0UkkgrlkLQ3iY1IUhAD1oASwi549RrRFa
ec4kAg/tFB58ocan74ULj9O8+VSHX9qoOGIpXrvZbYk96M6vvQ1Gfv973pLcpR62JZOiZuDUI4ThQuNR6/xxEHNV4E4e9l58zh8EpbwtrPLAvmn4xiOGf37M
cOxyxWUnaK44SfHqYzTLR/DEwN8TsN2pB8H5c7DrILzve96+fP1MfvAu8ew1gs4xs6BpeO3gH3vPCw+TnjDEi9vFn26ROX+P4Chwcl7Y5/cLn9nk8sUH4Ljl
ios2Ki4+zhODNUtA5WkjBn1yfsXMkPG/PQ1/8gP46QtQ7HfyCwzn4RVr/QFA6/xJ0MHegHEISTlxePPP+cOgmB00FIGn9wqP7xa++FNYs8TlnHWa8zcoXnWM
4pQjFEuLeH8tYVYQmi4xBWHwk14DLjz4Anzmfm/Ef7Laf+cHbwjl6CXC2Wsk4qaXReb8MfO2gz+hdf5eQynvFlZfDHYegm89bvjW47C0CEctVZx9pOLsdXDG
GsWpq2HlsPIS0B94aycK7Ryxqcy/gJb32qsgVRg/BHdtgX9+Au54DvZNeYN9/Rzxb0TVwAXrhRXDLQJgnT8W5sE04KA5f+ImUSIoVe8m1Jvb5ZrXOnjiReHr
D3vN3WVFOG6F4qRVihNWCsetUBwzCuuXKVaUvOTM6/rDOf6r7Q1JgAEx3hr/FRfGD8PjL8Jju+H+HfCTF7wdgqr17cEGwfV9CN7YyhUbxRPCtqsTL0LnT4AB
ngZspicoSInXH2jlvfztuFwDe6ZgfEL4962CCBRzQikHRQdGi3DEiGL1sLdCz5KC9yo69e3AlddsrrrCdA0OlhUHyrBrQthxyBuknKx4O+0oZjcILQ3YdmDg
fRbHLRcu2WBmNkG1zt9audePA7c9CSkIw4A5v3QpZD2CUvW7jBua4ILXUijXYP+0N7ho6gbvG/1MxZlAfjzxWv1q9qWAoQFy+iDUDLzpBGHliMwKwAys88fB
AE4DNtMTFKTEG3woZtfhG9QdfHsNI7CiBL96Wj3zrfPPJYiKfBpwAKcBB9T5LQYKZRfedorh9DWt7m+dPwkGaBqwmZ6gICWexaDCiLf82O+d7Xo9mVh/w0Xk
/Al4AzQNaJ3fIh7KLrzrpYaXr2t0f+v8nWAApgGb6QkKUuJFoGlUzSJrVA1sXC584BzXOn87QkLeAEwDWue3iAcRb8Dzz1/lsmGl1Of9rfMnOMkc9HEasJme
oCAlXgSsMPQd0y78xumGd5xm2kz7tcI6fxzEEAADaOv8Fn3FdA3OWSt84kLXuynKWOeP5En0nHAfpgGb6QkKUuJFwApD31ExsGGZ8LnX1hhbasAN+2Jb50+C
PkwDWue3iI+qgSNKwg1XuLxsXZt+v3X+YF4MbobTgM30BAUp8SJghaHvqLhwxBB88XUulx7vQs06f6+c30eG04ALxPk7Xb3XIhGmXThuVLjhtS6XbDTW+eOe
KCEvg2nAhhDJClLiRSBGctcMGONVVYvk3vusIOIl/3nrhM9dXuOMI03AY74zjNAfO+ctBOcXoh4G6MFDnnVxCOxzRHRGMud16OA+z8BLxhQnr1YI3sq/rung
72kxB9X65/iul7p8+z/XOGOtzE3+2GNSLRUTj2UF8WIGSsyLyqNe8zyk+DRgAz1ZQUq8CMQVBRd++STNeUdr7nrOcPMThrueE7YfFG/RjPoe9bZlEB9GvNt7
T1whfOR8wztOdUGJHe1vJHTK69/TgAuoz9/mVMuH4E1naN50qmLXQeHO54XvPyX86HnDC4dguuqtVuM/Y28xF37iLy/Cu89yef8rDBuWi3eTjwHb50+D14wU
pgEbeMkKUuJFoFNhMDKjrmuWKd72MsXbzoDxww53bzH84BlPDDbvh8PV2VV9/AU3FjNc8Ub4lxXgzScZ/uA/Gc5dV/8wa/UWZyCs88fmxeCmMA24gJ0/CP7S
3cDYEnjL6Zq3nCYcmtQ8uFP40Wbhx5uFh3cJ+6a8XXT8FYEbF/NYyBDx+vhGvF18X3+84ZozDa9eb7yRqKa+vnX+3vPao/cLPw2MMEQgLWFoaBksLcFrNipe
c7yiWhFeOAj3bRM2bRP+Ywc8+aJwsOwNJDraWxlY+a/Orm6gYMRz+5qBkTycvlp480mGt5xkOPkImd0RKXSU34d1/jR44QIw5SqGVL6pPTEwCT4Azt/ECzhW
f2glr+GYFXDMKsVbz1SUK7DjoPCTHcLPd8KDO+Gx3V4LYaLqJY1TX8TT7zYMcktB8D46U3d6rbwm/gkrhEuOEa443vDKtcLQkDS1mGY/t7QSvLMwC8L5ve9L
PqxKRAtg2RQcuhtHXTHn4YtWDIwwRCA1YQgol5b39S9+MQfHrVIcdwRcdSbUqnBgSvHkHuGR3fD4bnjiRW9J8D1T3sMw0zUvwXxR0Hq2pZBFq0Hq//h2YMSb
AjXirTo8nIcjlwgvXyucc6Rw/lHCKauEoWKdaJh1+9QTfJE7vwJqMg3q7jB25HdG/vaUP6Pk/CXTQfMJERcemDhZ8yLKO+bNedMZTzW8NOAKtaq3A8/WA/D0
Pnh+v7fi75YDsO2Qt17/ZNVzXH9df1+nG1sNqh5/Rixm/mm+hIZ23sy6J76rgzdmUXA88So5sG6JcMIKz+Vfsko4Y7Wwcbl4uxg51J1egltH7T63qITrmtdy
oO+8mHGT8pSAkb0sWbpBfXT34SB2nDGA0CaEdf4Yzh+ngjS86sg5sMyB04bhtHXM9JlNzZs+m6rCron66zDsnoC9097a/vum4FAFDtdfU/Vlw8tu/U7GemIr
vK6GVl43Zai+x8BIwWvCLyvCipKweti7L3/tEli/VFi/xEv04ZzMfov8Fo4QvEmndf72hHR4inKlmy4A1LeoDL6AIGQuDGkleBCvwwpJeP7blq3DtYYhDUMF
WDkCpzRZu8z0sY3xmuheM11mkt53dv8cqs5r3BvAoT5tqWV2dyH/mhoTHZoH8fqe4J2FSU8YUk3wcJ6Qpxy+KEC0ACi5m6pMo1SpKVms8yc63FNeQ/KGdUG0
Bq2EfLt9/CK7Lg3/u7TZeSfh59N3YVhUzu8JtlF3e+N4BwOrRQuAUT/GmEkcXfJOap2/owqp8ULChXGDymIneMx4URWt86fD04BWd6tPbpsKY0ULQJkCJQrR
F2advz+8ThM1LZ51/liEtHkKEBmOqhbjacBlU8Dd/pbRgQh0nAgr6pgnnSV5x7zwywmskBovKlzCAF3zElZMnRceJnagxLx6eeLr7CFPATUipwAhhgCoD9w3
hWETTtATgWkleHhxMC8tYcg6waN4WSd4zC9+wI/Z89JK8GTV5hCy4rlSRQ9FCkC8W4GFTd5AIKU5FxF4URFX2zGvE1XohtdhhdR4UeESBuial7Bi6rzwMLED
JeZJovCp8jRguIfaUORN1vEEYMrcjdJVnEYBSCvBY11RG15awpB1gkfxsk7whJ9P34UhrQRPVm0OITMe3hxuVTap68MHACHuikC5FTUU/46jmi8s0y5BWk37
IF745WTfJYgKl3WXIGHF1HnhYdLrEmTctI/kCdRMGe1sihMtlgCoD9w3Bep2lIqWpZ4LQwRsnz8iXFq8rBM8ipdWgierNoeQGa8BNfbC0h/FqRp/TcC8+ToV
d5KGRkAzrPNb529T0Tp/Rrx6gdepv5FP7pqMEzW+AEzX9gJ3e92A4PMnKIhVHMyzzh8ezjp/WJgF5/w+x6WM4jal4kWJLQDqfU+XQRq6AY1nts7fe15UOOv8
YWEWnfP7cGUvannk9J+PZMuC55XXDWhkWedPiWed3zp/fDqQuPkPSQVgurYX4T7vpiDr/Nb521S0zp8Rr02BiwvO7XGb/5BQALxugL4Wodz7wcAIWOePCGed
PyzMgnZ+8Ob+a9zBeZO3JwmTfFHQcv5eZHofObV25hHR1gtri4jf0t7hF8FLGKBrXsKKqfPCw8QOlJgnicKnzwso0IA2d6i3ts3KQCTfGuyDD02C+jxOK9U6
v3X+NHnW+RvpTVBARcYpVv4+abjEAqAUQr74GSrueG8GA9NK8CBe+OVkLwxR4bIWhoQVU+eFh0lPGLJO8CheSEBvwZfPqo+zK8kZocPNQdV7HxpH1GfJ6fAL
I7o4mGedPzycdf6wMIvC+cFb/LMq4+jyZzqI2sXuwF4rYC+608eErfOHh7POHxbGOn8dOcDlc+pTjCc5q4+OBUC996Fx4LcQcdsuLm6dP4Jnnd86f3x62wJH
oKr+jenyX3cQGeimBQCw5+0343InudZF5q3zJ4Z1/lhhrPM3FBtcjHxc3cCBJGduRFcCoD76UYOWT2AwM60A6/wRPOv81vnj0wMLckBN3cWrynd2EH0G3bUA
ANaedSc1c7M3EmmdPzGs88cKY52/oRjAcICc/K+k8/6t6Ml2cvJ361cyMfQUOVYG7vTa8y25OuXNedNnXkB533gJ46bOaznQM17MuJnx/OLAgtn/ikCZj6rr
y38RdJa46L4FAKh3bduLmGsQdWBOROv8EeGs84eFsc7fUuwAZW6mUL4+ydmD0BMBAFB/+MzN1ORvKNa3oYnj0LbP3wde1gkexUsrwZNVm0PIjNdMDy3Q1Ff7
KV+jPtH5wF8jeiYAAJTd65lyb56ZFbDOH8Kzzh8Wxjp/S7GXUgfQco26nr1JriAMPd9SXj61fiVO6SkctZJau8SJ0TJIcjySN+dNn3kB5X3jJYybOq/lQM94
MeNmxvOLAwuaeT3s9zeity0AQH1g215ErkGYDFw+rB2s86fES1jROn9GvJjOD5AHytzSq35/I3reAvAhnzz+DRT0VxAZ9baSts7fttw6f/ty6/weHMDlZnT5
HepTTASdrVP0vAXgQ33wmZupmr+h6D8wFADr/CnxEla0zp8RL4HzNw76pZD8/inSQ1WuZ8K9hUIHp7Gj/V3ysk7wKF5aCZ6s2hxCZrxmemSB55uTvR70a0Vq
XQAfct2aEXJLbqSgr6RsGgoiPj3btO+QlzBu6ryWA33nxYybGc8vbpP8yNvVX1duDorYC6QuANAiAhVTF7uEiRhVboUhgpcw7rwVhphx+5ngYTwHMNkkP6Td
BahD/dGuCWqH307F/Q6K9o8PRyGyyRVQITVeVLiEAbrmJayYOi88TOxAiXn18sTXmRYvImBjsZf841klP2TUAvAhN+Gw/fgrga+hZLjpMQbr/CnxEsa1zt8j
nl8c0/nzQJVb0OXf7nRxj06QqQD4kE8e+wZyzo04DFPxPwib4J3xEsadtwm+QIVBAQW8eX5dfntao/1ByKQL0Ar1wedvpua+BVduIx+4wUAdAU2oyKZaWryE
bcTUeS3lsU+TFi9moJ7xYhIy4zXTQwscQJikzEf7kfzQpxaAD/nIkcMsLX0dR/0KIg6msXDOmxaydf5Eca3z95nnFzckv9fff1dW/f126KsAAN64wJbjr8SR
r9kuQS94CePOW2GIGbdfCR7Eg8Ymf6b9/XbouwD4kGuPfS1F/X5y6nIqBoxN8PbHE8adtwm+wIQB8bfvmgSuQ5ev60eTvxUDIwCA1yVYUvjvKH6XvB6jKrMf
qHX+CF7CuPNWGGLGHSTnzwE1DEpuo6b+Rn26fGvQWbLGQAmAD7lu4xi470WpPyKvhqlKSItgzpuWcpvg6fBaDvSdFzNulsKg8ZbursltKHU9m8u3q290t4Zf
rzGQAuBDrj32tRTUf8PI5ThoajL3g7bOnyzuvBWGmHEHwfn9xK/IOKjPMlH+K3UDk0Fn6CcGWgAA5Coczt1wGUq9DyOXk1eaqjCrozbBs+W1HOg7L2bcLHgO
XvJXZBz4LLr8mX4P8kVh4AXAx4wQaHUhFfObFNQYBnBbWgXW+fvEazmwEBO8qVi87FF4ffwqBuE2MD9EVb446InvY94IQCPkuo1jSPU3EXUhDueh1SiCJwYd
jxUElNsEb1/ed17MuL3mqXrie6vzGpBxCnwJlx8OYh8/CvNSAHzIVThcuGE1k+ZqjC8GjKJgZrzA/0Na50+J13Jgvid4a7mfIRov6adlNukr/JBC+d5erdDb
D8xrAWjEjBgcNlejZBTD1WiGcPSo93y10LRIqTS8Zg7QXN7ueFS5TfCUeTHjJuGpluO6/lJ4Lu/IAQybyMkmKtw335O+EQtGAFoh124cRbtDmNrVCCVEFUGu
RlNEAIOmoEfR0v7LMnDCYAUlFk8IL2/n8GUMGC+hNeCqTSg2eVtvq/vI5TfxzIGD8615HwcLVgDaQa7dOIrUvAegHFWkWrsaTanpGYQZtD3YcNh/0/o8Vae8
AH7XvCikxYv5+cTmtZT3ipcDXHMfudKmmWMLNNktLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwWBf4/w5LyQw9j2z8AAAAASUVORK5CYII=
'@ -replace '\s', ''))

function Get-LogoImage([int]$size = 256) {
    $bmp = New-Object System.Windows.Media.Imaging.BitmapImage
    $bmp.BeginInit()
    $bmp.StreamSource = New-Object System.IO.MemoryStream(, $LogoPng)
    $bmp.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
    $bmp.DecodePixelWidth = $size
    $bmp.EndInit(); $bmp.Freeze()
    $bmp
}

function Get-LogoIcon {
    Add-Type -AssemblyName System.Drawing
    $ms = New-Object System.IO.MemoryStream(, $LogoPng)
    $b = New-Object System.Drawing.Bitmap($ms)
    $small = New-Object System.Drawing.Bitmap(32, 32)
    $g = [System.Drawing.Graphics]::FromImage($small)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.DrawImage($b, 0, 0, 32, 32); $g.Dispose()
    [System.Drawing.Icon]::FromHandle($small.GetHicon())
}

# ------------------------------------------------------------------ single instance
$script:ShowEvent = $null
try {
    $script:AppMutex = New-Object System.Threading.Mutex($false, 'Global\SilvanBoostMainInstance')
    $got = $false
    try { $got = $AppMutex.WaitOne($(if ($JustUpdated) { 15000 } else { 0 })) } catch [System.Threading.AbandonedMutexException] { $got = $true }
    $script:ShowEvent = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::AutoReset, 'Global\SilvanBoostShowWindow')
    if (-not $got) { [void]$ShowEvent.Set(); exit }
} catch { }

# ------------------------------------------------------------------ state + logging
$script:DataDir   = Join-Path $env:ProgramData 'SilvanBoost'
$script:StateFile = Join-Path $DataDir 'backup.json'
$script:LogFile   = Join-Path $DataDir 'silvanboost.log'
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

$script:LogLines = New-Object System.Collections.ArrayList
function Write-Log([string]$m) {
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
    [void]$LogLines.Add($line)
    while ($LogLines.Count -gt 200) { $LogLines.RemoveAt(0) }
    if ($script:LogView) { $script:LogView.Text = (@($LogLines) | Select-Object -Last 40) -join "`n" }
}

function ConvertTo-Hash($o) {
    if ($null -eq $o) { return $null }
    if ($o -is [System.Management.Automation.PSCustomObject]) {
        $h = @{}
        foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = ConvertTo-Hash $p.Value }
        return $h
    }
    if ($o -is [System.Collections.IEnumerable] -and $o -isnot [string]) {
        return , @($o | ForEach-Object { ConvertTo-Hash $_ })
    }
    return $o
}

function Load-State {
    $s = @{ reg = @{}; svc = @{}; misc = @{} }
    if (Test-Path -LiteralPath $StateFile) {
        try {
            $j = ConvertTo-Hash (Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json)
            foreach ($k in 'reg', 'svc', 'misc') { if ($j -and $j[$k] -is [hashtable]) { $s[$k] = $j[$k] } }
        } catch { Write-Log "Backup file could not be read: $_" }
    }
    $s
}
function Save-State {
    try { $script:State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $StateFile -Encoding UTF8 }
    catch { Write-Log "Could not save backup file: $_" }
}
$script:State = Load-State

# ------------------------------------------------------------------ registry helpers (with backup)
function Get-RegValue($Path, $Name) {
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($k.GetValueNames() -contains $Name) { return $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames') }
    } catch { }
    return $null
}

function Get-RegInfo($Path, $Name) {
    $r = @{ KeyExisted = [bool](Test-Path -LiteralPath $Path); Exists = $false; Value = $null; Type = $null }
    if ($r.KeyExisted) {
        $k = Get-Item -LiteralPath $Path
        if ($k.GetValueNames() -contains $Name) {
            $r.Exists = $true
            $r.Type = $k.GetValueKind($Name).ToString()
            $v = $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
            if ($v -is [byte[]]) { $v = [int[]]$v }
            $r.Value = $v
        }
    }
    $r
}

function Backup-Reg($Path, $Name) {
    $key = "$Path|$Name"
    if (-not $State.reg.ContainsKey($key)) { $State.reg[$key] = Get-RegInfo $Path $Name }
}

function Set-Reg($Path, $Name, $Value, $Type = 'DWord') {
    Backup-Reg $Path $Name
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Remove-RegVal($Path, $Name) {
    Backup-Reg $Path $Name
    if (Test-Path -LiteralPath $Path) { Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue }
}

function Restore-Reg($Path, $Name, $Default) {
    $key = "$Path|$Name"
    $b = $State.reg[$key]
    if ($b) {
        if ($b.Exists) {
            if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
            $v = $b.Value
            switch ($b.Type) {
                'Binary'      { $v = [byte[]]@($v) }
                'MultiString' { $v = [string[]]@($v) }
            }
            New-ItemProperty -LiteralPath $Path -Name $Name -Value $v -PropertyType $b.Type -Force | Out-Null
        } elseif (Test-Path -LiteralPath $Path) {
            Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
            if (-not $b.KeyExisted) {
                $k = Get-Item -LiteralPath $Path
                if ($k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0) { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue }
            }
        }
        $State.reg.Remove($key)
    } elseif ($null -ne $Default) {
        $t = 'DWord'; if ($Default -is [string]) { $t = 'String' }
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Default -PropertyType $t -Force | Out-Null
    } elseif (Test-Path -LiteralPath $Path) {
        Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    }
}

# ------------------------------------------------------------------ service helpers (with backup)
$script:SvcFallback = @{ SysMain = 'auto'; WSearch = 'delayed-auto'; DiagTrack = 'auto'; XblAuthManager = 'demand'; XblGameSave = 'demand'; XboxNetApiSvc = 'demand' }

function Disable-Svc($Name) {
    $p = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path -LiteralPath $p)) { return }
    if (-not $State.svc.ContainsKey($Name)) {
        $State.svc[$Name] = @{ Start = (Get-RegValue $p 'Start'); Delayed = (Get-RegValue $p 'DelayedAutostart') }
    }
    Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    $null = & sc.exe config $Name start= disabled
    if ($LASTEXITCODE -ne 0) { throw "Windows did not allow changing the service '$Name'." }
}

function Restore-Svc($Name) {
    $p = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path -LiteralPath $p)) { return }
    $mode = 'demand'
    if ($State.svc.ContainsKey($Name)) {
        $b = $State.svc[$Name]
        $map = @{ 0 = 'boot'; 1 = 'system'; 2 = 'auto'; 3 = 'demand'; 4 = 'disabled' }
        if ($null -ne $b.Start) { $mode = $map[[int]$b.Start] }
        if (-not $mode) { $mode = 'demand' }
        if ($mode -eq 'auto' -and $null -ne $b.Delayed -and [int]$b.Delayed -eq 1) { $mode = 'delayed-auto' }
        $State.svc.Remove($Name)
    } elseif ($SvcFallback.ContainsKey($Name)) { $mode = $SvcFallback[$Name] }
    $null = & sc.exe config $Name start= $mode
    if ($mode -like '*auto') { Start-Service -Name $Name -ErrorAction SilentlyContinue }
}

# ------------------------------------------------------------------ scheduled task helpers
function Split-TaskSpec([string]$Spec) {
    $i = $Spec.LastIndexOf('\')
    @($Spec.Substring(0, $i + 1), $Spec.Substring($i + 1))
}
function Set-TaskState([string]$Spec, [bool]$Enable) {
    $pn = Split-TaskSpec $Spec
    $t = Get-ScheduledTask -TaskPath $pn[0] -TaskName $pn[1] -ErrorAction SilentlyContinue
    if ($t) {
        if ($Enable) { $null = Enable-ScheduledTask -InputObject $t -ErrorAction SilentlyContinue }
        else { $null = Disable-ScheduledTask -InputObject $t -ErrorAction SilentlyContinue }
    }
}
function Test-TaskDisabled([string]$Spec) {
    $pn = Split-TaskSpec $Spec
    $t = Get-ScheduledTask -TaskPath $pn[0] -TaskName $pn[1] -ErrorAction SilentlyContinue
    if (-not $t) { return $true }
    return ([string]$t.State -eq 'Disabled')
}

# ------------------------------------------------------------------ power plan helpers
$script:GUID_RX  = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
$script:ULT_BASE = 'e9a42b02-d5df-448d-aa00-03f14749eb61'
$script:BALANCED = '381b4222-f694-41f0-9685-ff5bb260df2e'
$script:SUB_PROC = '54533251-82be-4824-96c1-47b60b740d00'
$script:CPMIN    = '0cc5b647-c1df-4637-891a-dec35c318583'
$script:SUB_USB  = '2a737441-1930-4402-8d77-b2bebba308a3'
$script:USBSS    = '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'
$script:SUB_PCIE = '501a4d13-42af-4429-9fd1-a8218c268e20'
$script:ASPM     = 'ee12f906-d277-404b-b6da-e5fa1a576df5'

function Get-ActiveScheme {
    $o = (powercfg /getactivescheme) | Out-String
    [regex]::Match($o, $GUID_RX).Value.ToLower()
}
function Get-ActiveSchemeName {
    $o = (powercfg /getactivescheme) | Out-String
    $m = [regex]::Match($o, '\(([^)]+)\)\s*$')
    if ($m.Success) { $m.Groups[1].Value } else { 'Unknown' }
}
function Get-PowerAC($Sub, $Set) {
    $o = (powercfg /query SCHEME_CURRENT $Sub $Set) | Out-String
    $m = [regex]::Matches($o, '0x[0-9a-fA-F]{8}')
    if ($m.Count -lt 2) { return $null }
    [Convert]::ToInt32($m[$m.Count - 2].Value, 16)
}
function Set-PowerAC($Sub, $Set, [int]$Val) {
    $k = "pw_$Set"
    if (-not $State.misc.ContainsKey($k)) {
        $cur = Get-PowerAC $Sub $Set
        if ($null -ne $cur) { $State.misc[$k] = $cur }
    }
    powercfg /setacvalueindex SCHEME_CURRENT $Sub $Set $Val | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'powercfg could not change this power setting.' }
    powercfg /setactive SCHEME_CURRENT | Out-Null
}
function Restore-PowerAC($Sub, $Set, [int]$Default) {
    $k = "pw_$Set"; $v = $Default
    if ($State.misc.ContainsKey($k)) { $v = [int]$State.misc[$k]; $State.misc.Remove($k) }
    powercfg /setacvalueindex SCHEME_CURRENT $Sub $Set $v | Out-Null
    powercfg /setactive SCHEME_CURRENT | Out-Null
}

# ------------------------------------------------------------------ misc helpers used by tweaks
function Get-UpNics { @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }) }

function Get-ActiveTcpIfaces {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
        $ip = @(@($p.DhcpIPAddress) + @($p.IPAddress) | Where-Object { $_ -and $_ -ne '0.0.0.0' })
        if ($ip.Count -gt 0) { "$base\$($_.PSChildName)" }
    }
}

function Get-NvMsiPath {
    $d = Get-PnpDevice -Class Display -PresentOnly -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -like 'PCI\VEN_10DE*' } | Select-Object -First 1
    if ($d) { "HKLM:\SYSTEM\CurrentControlSet\Enum\$($d.InstanceId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" }
}

function Restart-Explorer { Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue }

$script:CLSID_MENU = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}'
$script:BloatApps = @(
    'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.BingSearch', 'Microsoft.GetHelp', 'Microsoft.Getstarted',
    'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.People', 'Microsoft.WindowsFeedbackHub', 'Microsoft.WindowsMaps',
    'Microsoft.MicrosoftOfficeHub', 'Microsoft.Todos', 'Microsoft.PowerAutomateDesktop', 'Microsoft.Windows.DevHome',
    'Microsoft.549981C3F5F10', 'Microsoft.Copilot', 'Clipchamp.Clipchamp', 'MicrosoftTeams', 'MSTeams')

# ------------------------------------------------------------------ tweak catalogue
$script:Tweaks = New-Object System.Collections.ArrayList
function T {
    param(
        [string]$Id, [string]$Name, [string]$Cat, [string]$Desc, [string]$Risk = 'Safe',
        $Reg, $Svc, $Tasks, [scriptblock]$Apply, [scriptblock]$Revert, [scriptblock]$Check,
        [switch]$Reboot, [switch]$Action, [string]$Button = 'Run', [switch]$Permanent
    )
    [void]$script:Tweaks.Add(@{
        Id = $Id; Name = $Name; Cat = $Cat; Desc = $Desc; Risk = $Risk
        Reg = @($Reg); Svc = @($Svc); Tasks = @($Tasks)
        Apply = $Apply; Revert = $Revert; Check = $Check
        Reboot = [bool]$Reboot; Action = [bool]$Action; Button = $Button; Permanent = [bool]$Permanent
        Active = $false; LastMsg = $null; NotAvail = $null; Unfit = $null
    })
}
function R($Path, $Name, $Value, $Default) {
    $t = 'DWord'; if ($Value -is [string]) { $t = 'String' }
    @{ P = $Path; N = $Name; V = $Value; T = $t; D = $Default }
}
function RDel($Path, $Name) { @{ P = $Path; N = $Name; Del = $true } }

$CDM   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
$ADV   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$SP    = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
$GAMES = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
$GCS   = 'HKCU:\System\GameConfigStore'
$FS    = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
$MM    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
$GBAR  = 'HKCU:\Software\Microsoft\GameBar'

# ======================= FPS & LATENCY =======================
T -Id 'ultimate-plan' -Name 'Ultimate Performance Power Plan' -Cat 'FPS & Latency' `
  -Desc 'Unlocks and activates the hidden Ultimate Performance plan so your CPU stops down-clocking and parking cores between frames. Smoother frame times, higher idle power draw.' `
  -Apply {
    $cur = Get-ActiveScheme
    $g = [string]$State.misc['UltimateGuid']
    $list = (powercfg /list) | Out-String
    if (-not $g -or $list -notmatch [regex]::Escape($g)) {
        $o = (powercfg -duplicatescheme $ULT_BASE) | Out-String
        $g = [regex]::Match($o, $GUID_RX).Value.ToLower()
        if (-not $g) { throw 'Windows refused to create the Ultimate Performance plan.' }
        $State.misc['UltimateGuid'] = $g
    }
    if ($cur -ne $g -and -not $State.misc.ContainsKey('OrigScheme')) { $State.misc['OrigScheme'] = $cur }
    powercfg /setactive $g | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not activate the Ultimate Performance plan.' }
  } -Revert {
    $g = [string]$State.misc['UltimateGuid']; $o = [string]$State.misc['OrigScheme']
    if (-not $o -or $o -eq $g) { $o = $BALANCED }
    powercfg /setactive $o | Out-Null
    if ($g) { powercfg /delete $g | Out-Null }
    $State.misc.Remove('UltimateGuid'); $State.misc.Remove('OrigScheme')
  } -Check {
    $a = Get-ActiveScheme
    ($a -eq $ULT_BASE) -or ($State.misc['UltimateGuid'] -and $a -eq [string]$State.misc['UltimateGuid'])
  }

T -Id 'power-throttling' -Name 'Disable Power Throttling' -Cat 'FPS & Latency' `
  -Desc 'Stops Windows from throttling background processes (EcoQoS). Keeps launchers, overlays, Discord and voice chat at full speed instead of being pushed to slow states.' `
  -Reg (R 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling' 'PowerThrottlingOff' 1)

T -Id 'hags' -Name 'Hardware-Accelerated GPU Scheduling' -Cat 'FPS & Latency' -Reboot `
  -Desc 'Lets your graphics card schedule its own video memory instead of the CPU doing it. Lowers CPU overhead and render latency on modern NVIDIA, AMD and Intel GPUs.' `
  -Reg (R 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode' 2)

T -Id 'game-mode' -Name 'Enable Game Mode' -Cat 'FPS & Latency' `
  -Desc 'Tells Windows to prioritise the game you are playing and to hold back Windows Update installs and driver restarts while a game is running.' `
  -Reg @((R $GBAR 'AutoGameModeEnabled' 1), (R $GBAR 'AllowAutoGameMode' 1))

T -Id 'game-dvr' -Name 'Disable Game DVR & Background Recording' -Cat 'FPS & Latency' `
  -Desc 'Turns off Xbox background capture, which constantly records gameplay and costs frames. Use NVIDIA ShadowPlay instead if you want clips.' `
  -Reg @((R $GCS 'GameDVR_Enabled' 0),
         (R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled' 0),
         (R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' 'AllowGameDVR' 0))

T -Id 'fso' -Name 'Disable Fullscreen Optimizations' -Cat 'FPS & Latency' -Risk 'Moderate' `
  -Desc 'Forces true exclusive fullscreen in DirectX 9/11 games for lower input latency. Alt-tab becomes slower - leave this off if you mostly play borderless.' `
  -Reg @((R $GCS 'GameDVR_FSEBehaviorMode' 2), (R $GCS 'GameDVR_FSEBehavior' 2),
         (R $GCS 'GameDVR_HonorUserFSEBehaviorMode' 1), (R $GCS 'GameDVR_DXGIHonorFSEWindowsCompatible' 1))

T -Id 'mmcss-games' -Name 'Prioritize Games (MMCSS)' -Cat 'FPS & Latency' `
  -Desc 'Raises the Multimedia Class Scheduler profile for games: high CPU scheduling category, high I/O priority and top GPU priority.' `
  -Reg @((R $GAMES 'GPU Priority' 8 8), (R $GAMES 'Priority' 6 2),
         (R $GAMES 'Scheduling Category' 'High' 'Medium'), (R $GAMES 'SFIO Priority' 'High' 'Normal'))

T -Id 'sys-responsiveness' -Name 'Maximize System Responsiveness' -Cat 'FPS & Latency' `
  -Desc 'Reserves only 10% of CPU time for background multimedia tasks instead of 20%, giving the game more CPU time.' `
  -Reg (R $SP 'SystemResponsiveness' 10 20)

T -Id 'win32prio' -Name 'Foreground Priority Boost' -Cat 'FPS & Latency' `
  -Desc 'Uses short, variable CPU time slices with maximum boost for the foreground window (0x26), so the game gets the scheduler''s attention first.' `
  -Reg (R 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'Win32PrioritySeparation' 38 2)

T -Id 'timer-res' -Name 'Global Timer Resolution' -Cat 'FPS & Latency' -Risk 'Moderate' -Reboot `
  -Desc 'Restores system-wide high-resolution timer behaviour on Windows 11, so games that request 0.5-1 ms timers always get them. Lower frame-time jitter, slightly higher power use.' `
  -Reg (R 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'GlobalTimerResolutionRequests' 1)

T -Id 'core-parking' -Name 'Disable CPU Core Parking' -Cat 'FPS & Latency' -Risk 'Moderate' `
  -Desc 'Keeps all CPU cores (including E-cores on Intel hybrid CPUs) awake so game threads never wait for a parked core to wake up. Applies to the active power plan.' `
  -Apply { powercfg -attributes $SUB_PROC $CPMIN -ATTRIB_HIDE | Out-Null; Set-PowerAC $SUB_PROC $CPMIN 100 } `
  -Revert { Restore-PowerAC $SUB_PROC $CPMIN 10 } `
  -Check { (Get-PowerAC $SUB_PROC $CPMIN) -eq 100 }

T -Id 'usb-suspend' -Name 'Disable USB Selective Suspend' -Cat 'FPS & Latency' `
  -Desc 'Prevents Windows from putting your mouse, keyboard and headset USB ports to sleep, avoiding input drop-outs and wake-up lag.' `
  -Apply { Set-PowerAC $SUB_USB $USBSS 0 } -Revert { Restore-PowerAC $SUB_USB $USBSS 1 } `
  -Check { (Get-PowerAC $SUB_USB $USBSS) -eq 0 }

T -Id 'pcie-aspm' -Name 'Disable PCIe Power Saving' -Cat 'FPS & Latency' `
  -Desc 'Turns off PCIe Link State Power Management so the graphics card and NVMe SSD links never drop into low-power states mid-game.' `
  -Apply { Set-PowerAC $SUB_PCIE $ASPM 0 } -Revert { Restore-PowerAC $SUB_PCIE $ASPM 1 } `
  -Check { (Get-PowerAC $SUB_PCIE $ASPM) -eq 0 }

T -Id 'gpu-msi' -Name 'GPU Message Signaled Interrupts' -Cat 'FPS & Latency' -Risk 'Moderate' -Reboot `
  -Desc 'Makes sure your NVIDIA graphics card uses MSI interrupts instead of legacy line-based IRQs for lower interrupt latency. Recent NVIDIA drivers often enable this already.' `
  -Apply {
    $p = Get-NvMsiPath
    if (-not $p) { throw 'No NVIDIA GPU was detected.' }
    Set-Reg $p 'MSISupported' 1
  } -Revert {
    $p = Get-NvMsiPath
    if ($p) {
        if ($State.reg.ContainsKey("$p|MSISupported")) { Restore-Reg $p 'MSISupported' $null }
        else { throw 'MSI mode was enabled by your NVIDIA driver, so Silvan Boost leaves it on.' }
    }
  } -Check { $p = Get-NvMsiPath; [bool]($p -and (Get-RegValue $p 'MSISupported') -eq 1) }

T -Id 'dynamic-tick' -Name 'Disable Dynamic Tick' -Cat 'FPS & Latency' -Risk 'Advanced' -Reboot `
  -Desc 'Keeps the kernel timer ticking at a constant rate instead of pausing when idle. Can reduce micro-stutter and DPC latency spikes. If BitLocker is on, suspend it before restarting.' `
  -Apply {
    bcdedit /set '{current}' disabledynamictick yes | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'bcdedit could not change the boot configuration.' }
  } -Revert { bcdedit /deletevalue '{current}' disabledynamictick | Out-Null } `
  -Check {
    $o = (bcdedit /enum '{current}') | Out-String
    ($o -match 'disabledynamictick\s+(\S+)') -and ($Matches[1] -notmatch '^(No|Nein|Non)$')
  }

T -Id 'vbs' -Name 'Disable Memory Integrity (VBS)' -Cat 'FPS & Latency' -Risk 'Advanced' -Reboot `
  -Desc 'Turns off Virtualization-Based Security / Core Isolation, which Microsoft itself says can cost gaming performance. This lowers protection against kernel-level malware - only do it if you accept that trade-off.' `
  -Reg @((R 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled' 0),
         (R 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 0))

T -Id 'mouse-accel' -Name 'Disable Mouse Acceleration' -Cat 'FPS & Latency' `
  -Desc 'Turns off "Enhance pointer precision" for 1:1 raw mouse movement - essential for consistent aim. Applied instantly.' `
  -Reg @((R 'HKCU:\Control Panel\Mouse' 'MouseSpeed' '0' '1'),
         (R 'HKCU:\Control Panel\Mouse' 'MouseThreshold1' '0' '6'),
         (R 'HKCU:\Control Panel\Mouse' 'MouseThreshold2' '0' '10')) `
  -Apply { [void][SBNative]::SetMouseAccel($false) } `
  -Revert {
    $b = $State.reg['HKCU:\Control Panel\Mouse|MouseSpeed']
    $on = (-not $b) -or (-not $b.Exists) -or ([string]$b.Value -ne '0')
    [void][SBNative]::SetMouseAccel($on)
  }

# ======================= NETWORK & PING =======================
T -Id 'net-throttle' -Name 'Disable Network Throttling' -Cat 'Network & Ping' `
  -Desc 'Removes the packet-rate cap Windows applies to non-multimedia traffic while audio or video plays. Helps against ping spikes with Discord or music running.' `
  -Reg (R $SP 'NetworkThrottlingIndex' -1 10)

T -Id 'nagle' -Name "Disable Nagle's Algorithm" -Cat 'Network & Ping' -Risk 'Moderate' `
  -Desc 'Sends small TCP packets immediately instead of batching them. Helps TCP-based games (MMOs, some older titles); UDP shooters like Valorant or CS2 are unaffected.' `
  -Apply {
    $ifs = @(Get-ActiveTcpIfaces)
    if ($ifs.Count -eq 0) { throw 'No active network interface found.' }
    foreach ($i in $ifs) { Set-Reg $i 'TcpAckFrequency' 1; Set-Reg $i 'TCPNoDelay' 1 }
  } -Revert {
    foreach ($i in @(Get-ActiveTcpIfaces)) { Restore-Reg $i 'TcpAckFrequency' $null; Restore-Reg $i 'TCPNoDelay' $null }
  } -Check {
    $ifs = @(Get-ActiveTcpIfaces)
    if ($ifs.Count -eq 0) { return $false }
    foreach ($i in $ifs) { if ((Get-RegValue $i 'TcpAckFrequency') -ne 1 -or (Get-RegValue $i 'TCPNoDelay') -ne 1) { return $false } }
    $true
  }

T -Id 'nic-power' -Name 'Disable Network Adapter Power Saving' -Cat 'Network & Ping' `
  -Desc 'Stops Windows from switching off your Ethernet/Wi-Fi adapter to save power, a common cause of lag spikes and short disconnects.' `
  -Apply {
    $n = Get-UpNics
    if (-not $n) { throw 'No connected network adapter found.' }
    foreach ($a in $n) { Set-NetAdapterPowerManagement -Name $a.Name -AllowComputerToTurnOffDevice Disabled -ErrorAction SilentlyContinue }
  } -Revert {
    foreach ($a in Get-UpNics) { Set-NetAdapterPowerManagement -Name $a.Name -AllowComputerToTurnOffDevice Enabled -ErrorAction SilentlyContinue }
  } -Check {
    $n = Get-UpNics
    if (-not $n) { return $false }
    foreach ($a in $n) {
        $pm = Get-NetAdapterPowerManagement -Name $a.Name -ErrorAction SilentlyContinue
        if ($pm -and [string]$pm.AllowComputerToTurnOffDevice -eq 'Enabled') { return $false }
    }
    $true
  }

T -Id 'int-mod' -Name 'Disable Interrupt Moderation' -Cat 'Network & Ping' -Risk 'Advanced' `
  -Desc 'Makes the network card signal every packet immediately instead of batching them. Shaves network latency at the cost of a little CPU - modern CPUs have plenty. The connection blinks while applying.' `
  -Apply {
    $done = 0
    foreach ($a in Get-UpNics) {
        $p = Get-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword '*InterruptModeration' -ErrorAction SilentlyContinue
        if ($p) {
            $k = "im_$($a.InterfaceGuid)"
            if (-not $State.misc.ContainsKey($k)) { $State.misc[$k] = [string](@($p.RegistryValue)[0]) }
            Set-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword '*InterruptModeration' -RegistryValue '0' -ErrorAction Stop
            $done++
        }
    }
    if ($done -eq 0) { throw 'Your network adapter does not expose an Interrupt Moderation setting.' }
  } -Revert {
    foreach ($a in Get-UpNics) {
        $k = "im_$($a.InterfaceGuid)"; $v = '1'
        if ($State.misc.ContainsKey($k)) { $v = [string]$State.misc[$k]; $State.misc.Remove($k) }
        Set-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword '*InterruptModeration' -RegistryValue $v -ErrorAction SilentlyContinue
    }
  } -Check {
    $any = $false
    foreach ($a in Get-UpNics) {
        $p = Get-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword '*InterruptModeration' -ErrorAction SilentlyContinue
        if ($p) { $any = $true; if ([string](@($p.RegistryValue)[0]) -ne '0') { return $false } }
    }
    $any
  }

T -Id 'dns-cf' -Name 'Use Cloudflare DNS (1.1.1.1)' -Cat 'Network & Ping' -Risk 'Moderate' `
  -Desc 'Switches your connected adapters to Cloudflare''s fast public DNS for quicker lookups when connecting to game servers. Reverting restores your previous (usually router) DNS.' `
  -Apply {
    $n = Get-UpNics
    if (-not $n) { throw 'No connected network adapter found.' }
    foreach ($a in $n) {
        $k = "dns_$($a.InterfaceGuid)"
        if (-not $State.misc.ContainsKey($k)) {
            $State.misc[$k] = [string](Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($a.InterfaceGuid)" 'NameServer')
        }
        Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses @('1.1.1.1', '1.0.0.1') -ErrorAction Stop
    }
    Clear-DnsClientCache
  } -Revert {
    foreach ($a in Get-UpNics) {
        $k = "dns_$($a.InterfaceGuid)"; $o = ''
        if ($State.misc.ContainsKey($k)) { $o = [string]$State.misc[$k]; $State.misc.Remove($k) }
        if ($o) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses @($o -split '[,\s]+' | Where-Object { $_ }) }
        else { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses }
    }
    Clear-DnsClientCache
  } -Check {
    $n = Get-UpNics
    if (-not $n) { return $false }
    foreach ($a in $n) {
        $s = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
        if (@($s) -notcontains '1.1.1.1') { return $false }
    }
    $true
  }

T -Id 'delivery-opt' -Name 'Disable Update Peer Sharing' -Cat 'Network & Ping' `
  -Desc 'Stops Windows Update from uploading updates to other PCs over the internet (Delivery Optimization), which can eat upload bandwidth mid-match.' `
  -Reg (R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode' 0)

T -Id 'flush-dns' -Name 'Flush DNS Cache' -Cat 'Network & Ping' -Action -Button 'Flush' `
  -Desc 'Clears cached DNS entries. Fixes "can''t connect to server" problems after game server or network changes.' `
  -Apply { Clear-DnsClientCache; ipconfig /flushdns | Out-Null; 'DNS cache cleared' }

# ======================= MEMORY & STORAGE =======================
T -Id 'mem-compress' -Name 'Disable Memory Compression' -Cat 'Memory & Storage' -Risk 'Moderate' -Reboot `
  -Desc 'With 16 GB or more you rarely run out of RAM, so compressing memory just burns CPU cycles. Needs the SysMain service running while you toggle it.' `
  -Apply { Disable-MMAgent -MemoryCompression -ErrorAction Stop } `
  -Revert { Enable-MMAgent -MemoryCompression -ErrorAction Stop } `
  -Check { -not (Get-MMAgent -ErrorAction Stop).MemoryCompression }

T -Id 'sysmain' -Name 'Disable SysMain (Superfetch)' -Cat 'Memory & Storage' `
  -Desc 'SysMain preloads apps into RAM - pointless on a fast NVMe SSD and a known source of background disk and CPU spikes.' `
  -Svc 'SysMain'

T -Id 'paging-exec' -Name 'Keep Windows Kernel in RAM' -Cat 'Memory & Storage' -Reboot `
  -Desc 'Stops Windows from paging kernel and driver code out to disk. With 16 GB or more this costs nothing and avoids rare hitches.' `
  -Reg (R $MM 'DisablePagingExecutive' 1 0)

T -Id 'hibernation' -Name 'Disable Hibernation' -Cat 'Memory & Storage' `
  -Desc 'Deletes hiberfil.sys and frees several GB (about 40% of your RAM size) on your system drive. Also turns off Fast Startup.' `
  -Apply { powercfg /hibernate off | Out-Null } -Revert { powercfg /hibernate on | Out-Null } `
  -Check { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled') -eq 0 }

T -Id 'fast-startup' -Name 'Disable Fast Startup' -Cat 'Memory & Storage' `
  -Desc 'Makes Shut down a real shutdown so Windows and the NVIDIA driver fully reload. Fixes many "PC gets slower until I restart" issues.' `
  -Reg (R 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' 0 1)

T -Id 'last-access' -Name 'Disable NTFS Last-Access Timestamps' -Cat 'Memory & Storage' -Reboot `
  -Desc 'Stops Windows writing a timestamp every time a file is read. Fewer SSD writes while games stream thousands of asset files.' `
  -Reg (R $FS 'NtfsDisableLastAccessUpdate' -2147483647 -2147483646)

T -Id '8dot3' -Name 'Disable 8.3 Short File Names' -Cat 'Memory & Storage' -Reboot `
  -Desc 'Stops NTFS creating legacy DOS-style short names for every new file, speeding up file creation in big game folders.' `
  -Reg (R $FS 'NtfsDisable8dot3NameCreation' 1 2)

T -Id 'trim' -Name 'Ensure SSD TRIM Is Enabled' -Cat 'Memory & Storage' `
  -Desc 'Makes sure Windows tells your SSD which blocks are free, keeping write speed and lifespan at their best.' `
  -Reg (R $FS 'DisableDeleteNotification' 0 0)

T -Id 'search-index' -Name 'Disable Search Indexing' -Cat 'Memory & Storage' -Risk 'Moderate' `
  -Desc 'Stops the Windows Search indexer crawling your drive in the background. Searching for files in Start becomes slower; finding apps still works.' `
  -Svc 'WSearch'

T -Id 'retrim' -Name 'Optimize SSD Now (ReTrim)' -Cat 'Memory & Storage' -Action -Button 'Optimize' `
  -Desc 'Sends a full TRIM pass to all your SSD volumes so the controller can reclaim free blocks right away.' `
  -Apply {
    $done = @()
    foreach ($v in @(Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.FileSystem -eq 'NTFS' })) {
        try { Optimize-Volume -DriveLetter $v.DriveLetter -ReTrim -ErrorAction Stop; $done += "$($v.DriveLetter):" } catch { }
    }
    if ($done.Count -eq 0) { throw 'No SSD volume accepted a ReTrim.' }
    'Trimmed ' + ($done -join ' ')
  }

T -Id 'clean-temp' -Name 'Clean Temporary Files' -Cat 'Memory & Storage' -Action -Button 'Clean' `
  -Desc 'Deletes leftover files in your user and Windows temp folders. Files that are in use are skipped automatically.' `
  -Apply {
    $tot = 0.0
    foreach ($p in @($env:TEMP, (Join-Path $env:SystemRoot 'Temp'))) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $before = (Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        $after = (Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        $tot += [double]$before - [double]$after
    }
    'Freed {0:N0} MB' -f ($tot / 1MB)
  }

# ======================= REGISTRY =======================
T -Id 'startup-delay' -Name 'Remove Startup App Delay' -Cat 'Registry' `
  -Desc 'Windows waits several seconds after sign-in before launching startup apps. This removes the artificial delay.' `
  -Reg @((R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize' 'StartupDelayInMSec' 0),
         (R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize' 'WaitForIdleState' 0))

T -Id 'menu-delay' -Name 'Instant Menus' -Cat 'Registry' `
  -Desc 'Removes the 400 ms delay before menus and sub-menus open.' `
  -Reg (R 'HKCU:\Control Panel\Desktop' 'MenuShowDelay' '0' '400')

T -Id 'fast-shutdown' -Name 'Faster Shutdown' -Cat 'Registry' -Risk 'Moderate' `
  -Desc 'Gives hung apps and services 2 seconds instead of 5+ to close at shutdown. Save your work before shutting down, as always.' `
  -Reg @((R 'HKLM:\SYSTEM\CurrentControlSet\Control' 'WaitToKillServiceTimeout' '2000' '5000'),
         (R 'HKCU:\Control Panel\Desktop' 'WaitToKillAppTimeout' '2000'),
         (R 'HKCU:\Control Panel\Desktop' 'HungAppTimeout' '2000'))

T -Id 'wer' -Name 'Disable Windows Error Reporting' -Cat 'Registry' `
  -Desc 'Stops Windows collecting and uploading crash dumps after every app or game crash, which can freeze the PC for several seconds.' `
  -Reg @((R 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1),
         (R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1))

T -Id 'remote-assist' -Name 'Disable Remote Assistance' -Cat 'Registry' `
  -Desc 'Turns off unsolicited Remote Assistance connections. One less listening service and attack surface.' `
  -Reg (R 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0 1)

T -Id 'transparency' -Name 'Disable Transparency Effects' -Cat 'Registry' `
  -Desc 'Turns off the acrylic blur in the taskbar and Start menu, removing a little constant work from the desktop compositor.' `
  -Reg (R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' 'EnableTransparency' 0 1)

T -Id 'animations' -Name 'Disable Window Animations' -Cat 'Registry' -Reboot `
  -Desc 'Removes minimize/maximize and taskbar animations so alt-tabbing in and out of games feels instant. Takes effect after sign-out.' `
  -Reg @((R 'HKCU:\Control Panel\Desktop\WindowMetrics' 'MinAnimate' '0' '1'), (R $ADV 'TaskbarAnimations' 0 1))

T -Id 'bg-apps' -Name 'Disable Background Apps' -Cat 'Registry' `
  -Desc 'Stops Microsoft Store apps from running in the background when you are not using them.' `
  -Reg @((R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' 'GlobalUserDisabled' 1 0),
         (R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' 'BackgroundAppGlobalToggle' 0 1))

# ======================= DEBLOAT =======================
T -Id 'copilot' -Name 'Disable Copilot' -Cat 'Debloat' `
  -Desc 'Hides Copilot from the taskbar and turns off the Windows Copilot integration.' `
  -Reg @((R 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 1), (R $ADV 'ShowCopilotButton' 0))

T -Id 'recall' -Name 'Disable Recall & AI Snapshots' -Cat 'Debloat' `
  -Desc 'Prevents Windows Recall from taking and analysing screenshots of everything you do.' `
  -Reg @((R 'HKCU:\Software\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 1),
         (R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 1))

T -Id 'widgets' -Name 'Disable Widgets' -Cat 'Debloat' `
  -Desc 'Removes the Widgets board and its background news feed process (Widgets.exe / WebView2).' `
  -Reg (R 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' 0)

T -Id 'cortana' -Name 'Disable Cortana' -Cat 'Debloat' `
  -Desc 'Turns off Cortana so it cannot run or use CPU and disk in the background.' `
  -Reg (R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCortana' 0)

T -Id 'bing-search' -Name 'Disable Web Results in Start Search' -Cat 'Debloat' `
  -Desc 'Start search only searches your PC - no Bing results, no network round-trip, faster results.' `
  -Reg @((R 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 1),
         (R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' 'BingSearchEnabled' 0))

T -Id 'start-ads' -Name 'Remove Start Menu Ads & Auto-Installed Apps' -Cat 'Debloat' `
  -Desc 'Stops Windows silently installing promoted apps and removes suggestions and recommendations from Start.' `
  -Reg @((R $CDM 'SystemPaneSuggestionsEnabled' 0), (R $CDM 'SilentInstalledAppsEnabled' 0),
         (R $CDM 'PreInstalledAppsEnabled' 0), (R $CDM 'OemPreInstalledAppsEnabled' 0),
         (R $CDM 'SoftLandingEnabled' 0), (R $CDM 'SubscribedContent-338388Enabled' 0),
         (R $CDM 'SubscribedContent-338389Enabled' 0), (R $ADV 'Start_IrisRecommendations' 0))

T -Id 'settings-ads' -Name 'Remove Windows Settings Ads' -Cat 'Debloat' `
  -Desc 'Removes promotional suggestions and offers from the Settings app.' `
  -Reg @((R $CDM 'SubscribedContent-338393Enabled' 0), (R $CDM 'SubscribedContent-353694Enabled' 0),
         (R $CDM 'SubscribedContent-353696Enabled' 0))

T -Id 'lock-ads' -Name 'Disable Lock Screen Tips & Ads' -Cat 'Debloat' `
  -Desc 'Removes fun facts, tips and promotions from the lock screen.' `
  -Reg @((R $CDM 'RotatingLockScreenOverlayEnabled' 0), (R $CDM 'SubscribedContent-338387Enabled' 0))

T -Id 'tips' -Name 'Disable Tips & "Finish Setup" Nags' -Cat 'Debloat' `
  -Desc 'Stops the "Let''s finish setting up your device" screens and tip notifications.' `
  -Reg @((R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement' 'ScoobeSystemSettingEnabled' 0),
         (R $CDM 'SubscribedContent-310093Enabled' 0),
         (R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested' 'Enabled' 0))

T -Id 'edge-bg' -Name 'Stop Edge Running in Background' -Cat 'Debloat' `
  -Desc 'Disables Edge Startup Boost and background mode so Edge does not sit in RAM when closed. Edge will say it is "managed by your organization" - that is normal for policies.' `
  -Reg @((R 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'StartupBoostEnabled' 0),
         (R 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'BackgroundModeEnabled' 0))

T -Id 'onedrive-start' -Name 'Stop OneDrive Auto-Start' -Cat 'Debloat' `
  -Desc 'Prevents OneDrive from launching and syncing at boot. You can still open it manually any time.' `
  -Reg (RDel 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' 'OneDrive')

T -Id 'xbox-svc' -Name 'Disable Xbox Services' -Cat 'Debloat' -Risk 'Moderate' `
  -Desc 'Turns off Xbox Live sign-in, cloud-save and networking services. Leave this OFF if you use Game Pass, the Xbox app or Xbox cloud saves.' `
  -Svc @('XblAuthManager', 'XblGameSave', 'XboxNetApiSvc')

T -Id 'gamebar' -Name 'Disable Xbox Game Bar Overlay' -Cat 'Debloat' -Risk 'Moderate' `
  -Desc 'Stops the Win+G overlay hooking into games. Game Mode keeps working.' `
  -Reg @((R $GBAR 'UseNexusForGameBarEnabled' 0), (R $GBAR 'ShowStartupPanel' 0))

T -Id 'bloat-apps' -Name 'App Cleaner: Remove Unneeded Apps' -Cat 'Debloat' -Action -Button 'Open' `
  -Desc 'Opens the App Cleaner, where you pick exactly which preinstalled apps (News, Solitaire, Clipchamp, Candy Crush, TikTok ...) get removed.' `
  -Apply { $NavApps.IsChecked = $true; 'Opened App Cleaner' }

# ======================= PRIVACY =======================
T -Id 'telemetry' -Name 'Minimize Windows Telemetry' -Cat 'Privacy' `
  -Desc 'Sets diagnostic data to the minimum your edition allows and stops the Connected User Experiences & Telemetry service that uploads usage data in the background.' `
  -Reg @((R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 0),
         (R 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' 'AllowTelemetry' 0)) `
  -Svc @('DiagTrack', 'dmwappushservice')

T -Id 'telemetry-tasks' -Name 'Disable Telemetry Scheduled Tasks' -Cat 'Privacy' `
  -Desc 'Disables the Compatibility Appraiser, CEIP and feedback tasks that wake up in the background and scan your PC.' `
  -Tasks @('\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
           '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
           '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
           '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
           '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
           '\Microsoft\Windows\Feedback\Siuf\DmClient',
           '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload')

T -Id 'ad-id' -Name 'Disable Advertising ID' -Cat 'Privacy' `
  -Desc 'Stops apps using your advertising ID to show personalised ads across apps.' `
  -Reg (R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 0)

T -Id 'activity' -Name 'Disable Activity History' -Cat 'Privacy' `
  -Desc 'Stops Windows recording and uploading a timeline of the apps and files you use.' `
  -Reg @((R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableActivityFeed' 0),
         (R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'PublishUserActivities' 0),
         (R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'UploadUserActivities' 0))

T -Id 'tailored' -Name 'Disable Tailored Experiences' -Cat 'Privacy' `
  -Desc 'Stops Microsoft using your diagnostic data to show personalised tips, ads and recommendations.' `
  -Reg (R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 0)

T -Id 'feedback' -Name 'Disable Feedback Prompts' -Cat 'Privacy' `
  -Desc 'No more "How likely are you to recommend Windows?" pop-ups.' `
  -Reg @((R 'HKCU:\Software\Microsoft\Siuf\Rules' 'NumberOfSIUFInPeriod' 0),
         (R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DoNotShowFeedbackNotifications' 1))

T -Id 'nvidia-tel' -Name 'Disable NVIDIA Telemetry' -Cat 'Privacy' `
  -Desc 'Opts out of NVIDIA driver telemetry and stops the NVIDIA telemetry container service if your driver has one.' `
  -Reg @((R 'HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client' 'OptInOrOutPreference' 0),
         (R 'HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup' 'SendTelemetryData' 0)) `
  -Svc 'NvTelemetryContainer'

T -Id 'firefox-tel' -Name 'Disable Firefox Telemetry' -Cat 'Privacy' `
  -Desc 'Stops Firefox sending usage and performance data to Mozilla.' `
  -Reg (R 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox' 'DisableTelemetry' 1)

T -Id 'location' -Name 'Disable Location Access' -Cat 'Privacy' -Risk 'Moderate' `
  -Desc 'Blocks all apps from using your location. Automatic time zone and local weather will stop working.' `
  -Reg (R 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' 'Value' 'Deny' 'Allow')

# ======================= QUALITY OF LIFE =======================
T -Id 'sticky-keys' -Name 'Disable Sticky Keys Pop-up' -Cat 'Quality of Life' `
  -Desc 'No more Sticky Keys pop-up when you tap Shift five times mid-game. Also disables the Filter Keys and Toggle Keys shortcuts.' `
  -Reg @((R 'HKCU:\Control Panel\Accessibility\StickyKeys' 'Flags' '506' '510'),
         (R 'HKCU:\Control Panel\Accessibility\Keyboard Response' 'Flags' '122' '126'),
         (R 'HKCU:\Control Panel\Accessibility\ToggleKeys' 'Flags' '58' '62'))

T -Id 'kbd-repeat' -Name 'Fastest Keyboard Repeat' -Cat 'Quality of Life' `
  -Desc 'Shortest delay before a held key starts repeating, at the fastest repeat rate. Takes effect after sign-out.' `
  -Reg @((R 'HKCU:\Control Panel\Keyboard' 'KeyboardDelay' '0' '1'), (R 'HKCU:\Control Panel\Keyboard' 'KeyboardSpeed' '31' '31'))

T -Id 'verbose' -Name 'Show Detailed Boot Messages' -Cat 'Quality of Life' `
  -Desc 'Shows what Windows is doing during startup and shutdown. Does not speed things up, but makes hangs easy to diagnose.' `
  -Reg (R 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'VerboseStatus' 1)

T -Id 'file-ext' -Name 'Show File Extensions' -Cat 'Quality of Life' `
  -Desc 'Always show .exe, .zip, .cfg and other extensions - handy when editing game configs and safer against fake files.' `
  -Reg (R $ADV 'HideFileExt' 0 1)

T -Id 'classic-menu' -Name 'Classic Right-Click Menu' -Cat 'Quality of Life' `
  -Desc 'Brings back the full Windows 10 right-click menu without the extra "Show more options" click. Explorer restarts automatically.' `
  -Apply {
    $p = "$CLSID_MENU\InprocServer32"
    New-Item -Path $p -Force | Out-Null
    Set-ItemProperty -LiteralPath $p -Name '(default)' -Value ''
    Restart-Explorer
  } -Revert {
    if (Test-Path -LiteralPath $CLSID_MENU) { Remove-Item -LiteralPath $CLSID_MENU -Recurse -Force }
    Restart-Explorer
  } -Check { Test-Path -LiteralPath "$CLSID_MENU\InprocServer32" }

T -Id 'this-pc' -Name 'Open Explorer to This PC' -Cat 'Quality of Life' `
  -Desc 'File Explorer opens straight to your drives instead of Home / Quick access.' `
  -Reg (R $ADV 'LaunchTo' 1)

T -Id 'quick-access' -Name 'Hide Recent Files in Quick Access' -Cat 'Quality of Life' `
  -Desc 'Stops Explorer listing recently opened files and frequent folders.' `
  -Reg @((R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' 'ShowRecent' 0 1),
         (R 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' 'ShowFrequent' 0 1))

# ======================= PROCESSES =======================
T -Id 'svchost-group' -Name 'Group Windows Services (fewer svchost)' -Cat 'Processes' -Risk 'Moderate' -Reboot `
  -Desc 'With more than 3.5 GB RAM Windows starts every service in its own svchost.exe. Grouping them again removes roughly 30-80 processes after a restart. Trade-off: if one service crashes, its group restarts with it.' `
  -Apply {
    $kb = [int64][Math]::Ceiling([double](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1KB) + 1024
    if ($kb -gt [int]::MaxValue) { $kb = [int]::MaxValue }
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control' 'SvcHostSplitThresholdInKB' ([int]$kb)
  } -Revert { Restore-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control' 'SvcHostSplitThresholdInKB' 3670016 } `
  -Check {
    $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control' 'SvcHostSplitThresholdInKB'
    $ram = [double](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1KB
    ($null -ne $v) -and ([double]([uint32]([int64]$v -band 0xFFFFFFFFL)) -ge $ram)
  }

T -Id 'extra-services' -Name 'Disable Unneeded Services' -Cat 'Processes' -Risk 'Moderate' `
  -Desc 'Turns off services almost no gaming PC needs: Fax, Remote Registry, Offline Maps, Retail Demo, Windows Insider, Media Player network sharing, Link Tracking, Parental Controls, NFC Payments and the Program Compatibility Assistant.' `
  -Svc @('Fax', 'RemoteRegistry', 'MapsBroker', 'RetailDemo', 'wisvc', 'WMPNetworkSvc', 'TrkWks', 'WpcMonSvc', 'SEMgrSvc', 'PcaSvc')

T -Id 'print-spooler' -Name 'Disable Print Spooler' -Cat 'Processes' `
  -Desc 'Stops the printing service. Only do this if you do not use a printer - turn it back on any time you need to print.' `
  -Svc 'Spooler'

# ======================= NETWORK (extra) =======================
$script:EeeKeys = @('*EEE', 'EEE', 'EEELinkAdvertisement', 'AdvancedEEE', 'EnableGreenEthernet', 'GreenEthernet', '*GreenEthernet',
    'PowerSavingMode', 'GigaLite', 'ReduceSpeedOnPowerDown', 'ULPMode', '*SelectiveSuspend')
$script:LsoKeys = @('*LsoV2IPv4', '*LsoV2IPv6', '*LsoV1IPv4')

function Get-NicProps($a, $keys) {
    @(Get-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -RegistryKeyword $keys -ErrorAction SilentlyContinue |
        Where-Object { -not $_.ValidRegistryValues -or @($_.ValidRegistryValues) -contains '0' })
}
function Set-NicProps($keys, [string]$tag) {
    $done = 0
    foreach ($a in Get-UpNics) {
        $changed = $false
        foreach ($p in Get-NicProps $a $keys) {
            $cur = [string](@($p.RegistryValue)[0])
            $k = "${tag}_$($a.InterfaceGuid)_$($p.RegistryKeyword)"
            if (-not $State.misc.ContainsKey($k)) { $State.misc[$k] = $cur }
            if ($cur -ne '0') {
                Set-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -RegistryKeyword $p.RegistryKeyword -RegistryValue '0' -NoRestart -ErrorAction Stop
                $changed = $true
            }
            $done++
        }
        if ($changed) { Restart-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue }
    }
    if ($done -eq 0) { throw 'Your network adapter does not expose these settings.' }
    Wait-NicsUp
}
function Restore-NicProps($keys, [string]$tag) {
    foreach ($a in Get-UpNics) {
        $changed = $false
        foreach ($p in Get-NicProps $a $keys) {
            $k = "${tag}_$($a.InterfaceGuid)_$($p.RegistryKeyword)"
            if (-not $State.misc.ContainsKey($k)) { continue }
            $v = [string]$State.misc[$k]; $State.misc.Remove($k)
            if ([string](@($p.RegistryValue)[0]) -ne $v) {
                Set-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -RegistryKeyword $p.RegistryKeyword -RegistryValue $v -NoRestart -ErrorAction SilentlyContinue
                $changed = $true
            }
        }
        if ($changed) { Restart-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue }
    }
}
function Test-NicProps($keys) {
    $any = $false
    foreach ($a in Get-UpNics) {
        foreach ($p in Get-NicProps $a $keys) { $any = $true; if ([string](@($p.RegistryValue)[0]) -ne '0') { return $false } }
    }
    $any
}
function Get-AllGameExes {
    $l = New-Object System.Collections.ArrayList
    foreach ($g in $GameCatalog) { foreach ($e in $g.Exes) { if ($e) { [void]$l.Add($e) } } }
    foreach ($c in @($State.misc['CustomGames'])) { if ($c -and $c.Exe) { [void]$l.Add([IO.Path]::GetFileName([string]$c.Exe)) } }
    @($l | Sort-Object -Unique)
}

T -Id 'nic-eee' -Name 'Disable Network Adapter Energy Saving' -Cat 'Network & Ping' `
  -Desc 'Turns off Energy-Efficient Ethernet, Green Ethernet and similar adapter power features that put the link to sleep between packets and cause small ping spikes. The connection drops for a few seconds while applying.' `
  -Apply { Set-NicProps $EeeKeys 'eee' } -Revert { Restore-NicProps $EeeKeys 'eee' } -Check { Test-NicProps $EeeKeys }

T -Id 'nic-lso' -Name 'Disable Large Send Offload' -Cat 'Network & Ping' -Risk 'Moderate' `
  -Desc 'Stops the network card from collecting outgoing data into big chunks before sending. Small game packets leave right away. The connection drops for a few seconds while applying.' `
  -Apply { Set-NicProps $LsoKeys 'lso' } -Revert { Restore-NicProps $LsoKeys 'lso' } -Check { Test-NicProps $LsoKeys }

T -Id 'qos-games' -Name 'Prioritize Game Traffic (QoS)' -Cat 'Network & Ping' `
  -Desc 'Marks the network packets of all known games (and your own added games) as top priority (DSCP 46). Wi-Fi and routers that support QoS / WMM send them first when the connection is busy.' `
  -Apply {
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' 'Do not use NLA' '1' 'String'
    foreach ($e in Get-AllGameExes) {
        $n = "SilvanBoost $e"
        Remove-NetQosPolicy -Name $n -Confirm:$false -ErrorAction SilentlyContinue
        New-NetQosPolicy -Name $n -AppPathNameMatchCondition $e -DSCPAction 46 -NetworkProfile All -ErrorAction Stop | Out-Null
    }
  } -Revert {
    Get-NetQosPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'SilvanBoost *' } | ForEach-Object { Remove-NetQosPolicy -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue }
    Restore-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' 'Do not use NLA' $null
  } -Check { @(Get-NetQosPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'SilvanBoost *' }).Count -gt 0 }

T -Id 'do-limit' -Name 'Limit Background Update Downloads' -Cat 'Network & Ping' `
  -Desc 'Windows Update and Store downloads in the background may use at most 10% of your bandwidth, so they cannot flood your connection and spike your ping mid-match.' `
  -Reg (R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DOPercentageMaxBackgroundBandwidth' 10)

# ======================= NETWORK (advanced adapter settings) =======================
$script:FlowKeys = @('*FlowControl')
$script:BufKeys  = @('*ReceiveBuffers', '*TransmitBuffers')
$script:RoamKeys = @('RoamAggressiveness', '*RoamAggressiveness', 'RoamingAggressiveness')

function Wait-NicsUp([int]$want = 1) {
    if ($want -lt 1) { $want = 1 }
    Start-Sleep -Milliseconds 800
    for ($i = 0; $i -lt 30; $i++) {
        if (@(Get-UpNics).Count -ge $want) { break }
        Start-Sleep -Milliseconds 500
        Flush-UI
    }
}

function Get-NicTarget($p, [string]$mode) {
    $valid = @($p.ValidRegistryValues | Where-Object { $_ -ne $null -and "$_" -match '^-?\d+$' } | ForEach-Object { [int64]"$_" } | Sort-Object)
    switch ($mode) {
        'zero' { if ($valid.Count -eq 0 -or $valid -contains 0) { return '0' } }
        'max' {
            if ($valid.Count -gt 0) { return [string]$valid[-1] }
            if ($p.NumericParameterMaxValue) { return [string][int64]$p.NumericParameterMaxValue }
        }
        'min' {
            if ($valid.Count -gt 0) { return [string]$valid[0] }
            if ($null -ne $p.NumericParameterMinValue) { return [string][int64]$p.NumericParameterMinValue }
        }
    }
    $null
}

function Get-NicModeProps($a, $keys, [string]$mode) {
    @(Get-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -RegistryKeyword $keys -ErrorAction SilentlyContinue |
        Where-Object { $null -ne (Get-NicTarget $_ $mode) })
}

function Set-NicMode($keys, [string]$tag, [string]$mode) {
    $before = @(Get-UpNics).Count
    $done = 0
    foreach ($a in Get-UpNics) {
        $changed = $false
        foreach ($p in Get-NicModeProps $a $keys $mode) {
            $want = Get-NicTarget $p $mode
            $cur = [string](@($p.RegistryValue)[0])
            $k = "${tag}_$($a.InterfaceGuid)_$($p.RegistryKeyword)"
            if (-not $State.misc.ContainsKey($k)) { $State.misc[$k] = $cur }
            if ($cur -ne $want) {
                Set-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -RegistryKeyword $p.RegistryKeyword -RegistryValue $want -NoRestart -ErrorAction Stop
                $changed = $true
            }
            $done++
        }
        if ($changed) { Restart-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue }
    }
    if ($done -eq 0) { throw 'Your network adapter does not expose this setting.' }
    Wait-NicsUp $before
}

function Restore-NicMode($keys, [string]$tag) {
    $before = @(Get-UpNics).Count
    foreach ($a in Get-UpNics) {
        $changed = $false
        foreach ($p in @(Get-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -RegistryKeyword $keys -ErrorAction SilentlyContinue)) {
            $k = "${tag}_$($a.InterfaceGuid)_$($p.RegistryKeyword)"
            if (-not $State.misc.ContainsKey($k)) { continue }
            $v = [string]$State.misc[$k]; $State.misc.Remove($k)
            if ([string](@($p.RegistryValue)[0]) -ne $v) {
                Set-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -RegistryKeyword $p.RegistryKeyword -RegistryValue $v -NoRestart -ErrorAction SilentlyContinue
                $changed = $true
            }
        }
        if ($changed) { Restart-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue }
    }
    Wait-NicsUp $before
}

function Test-NicMode($keys, [string]$mode) {
    $any = $false
    foreach ($a in Get-UpNics) {
        foreach ($p in Get-NicModeProps $a $keys $mode) {
            $any = $true
            if ([string](@($p.RegistryValue)[0]) -ne (Get-NicTarget $p $mode)) { return $false }
        }
    }
    $any
}

function Test-NicHas($keys, [string]$mode) {
    foreach ($a in Get-UpNics) { if (@(Get-NicModeProps $a $keys $mode).Count -gt 0) { return $true } }
    $false
}

T -Id 'nic-rsc' -Name 'Disable Receive Segment Coalescing' -Cat 'Network & Ping' `
  -Desc 'Stops the network card from holding incoming packets back to merge them into bigger chunks. Game packets reach the game immediately instead of waiting to be bundled.' `
  -Apply {
    $n = 0
    foreach ($a in Get-UpNics) {
        $r = Get-NetAdapterRsc -Name $a.Name -ErrorAction SilentlyContinue
        if (-not $r) { continue }
        $k = "rsc_$($a.InterfaceGuid)"
        if (-not $State.misc.ContainsKey($k)) { $State.misc[$k] = "$([bool]$r.IPv4Enabled),$([bool]$r.IPv6Enabled)" }
        Disable-NetAdapterRsc -Name $a.Name -ErrorAction Stop
        $n++
    }
    if ($n -eq 0) { throw 'Your network adapter does not support this setting.' }
    Wait-NicsUp
  } -Revert {
    foreach ($a in Get-UpNics) {
        $k = "rsc_$($a.InterfaceGuid)"
        if (-not $State.misc.ContainsKey($k)) { continue }
        $v = ([string]$State.misc[$k]).Split(','); $State.misc.Remove($k)
        if ($v[0] -eq 'True') { Enable-NetAdapterRsc -Name $a.Name -IPv4 -ErrorAction SilentlyContinue }
        if ($v[1] -eq 'True') { Enable-NetAdapterRsc -Name $a.Name -IPv6 -ErrorAction SilentlyContinue }
    }
    Wait-NicsUp
  } -Check {
    $any = $false
    foreach ($a in Get-UpNics) {
        $r = Get-NetAdapterRsc -Name $a.Name -ErrorAction SilentlyContinue
        if (-not $r) { continue }
        $any = $true
        if ($r.IPv4Enabled -or $r.IPv6Enabled) { return $false }
    }
    $any
  }

T -Id 'nic-rss' -Name 'Enable Receive Side Scaling' -Cat 'Network & Ping' `
  -Desc 'Lets several CPU cores process incoming network traffic instead of one, so a busy core never delays your game packets.' `
  -Apply {
    $n = 0
    foreach ($a in Get-UpNics) {
        $r = Get-NetAdapterRss -Name $a.Name -ErrorAction SilentlyContinue
        if (-not $r) { continue }
        $k = "rss_$($a.InterfaceGuid)"
        if (-not $State.misc.ContainsKey($k)) { $State.misc[$k] = [string][bool]$r.Enabled }
        if (-not $r.Enabled) { Enable-NetAdapterRss -Name $a.Name -ErrorAction Stop }
        $n++
    }
    if ($n -eq 0) { throw 'Your network adapter does not support Receive Side Scaling.' }
    Wait-NicsUp
  } -Revert {
    foreach ($a in Get-UpNics) {
        $k = "rss_$($a.InterfaceGuid)"
        if (-not $State.misc.ContainsKey($k)) { continue }
        $was = [string]$State.misc[$k]; $State.misc.Remove($k)
        if ($was -eq 'False') { Disable-NetAdapterRss -Name $a.Name -ErrorAction SilentlyContinue }
    }
    Wait-NicsUp
  } -Check {
    $any = $false
    foreach ($a in Get-UpNics) {
        $r = Get-NetAdapterRss -Name $a.Name -ErrorAction SilentlyContinue
        if (-not $r) { continue }
        $any = $true
        if (-not $r.Enabled) { return $false }
    }
    $any
  }

T -Id 'nic-buffers' -Name 'Maximum Network Buffers (no packet drops)' -Cat 'Network & Ping' `
  -Desc 'Sets the receive and transmit buffers of your network card to the maximum, so bursts of traffic (downloads, voice chat, game updates) never cause dropped packets. Uses a few MB of RAM. The connection drops for a few seconds while applying.' `
  -Apply { Set-NicMode $BufKeys 'buf' 'max' } -Revert { Restore-NicMode $BufKeys 'buf' } -Check { Test-NicMode $BufKeys 'max' }

T -Id 'wifi-roam' -Name 'Wi-Fi: Lowest Roaming Aggressiveness' -Cat 'Network & Ping' `
  -Desc 'Stops your Wi-Fi card from constantly scanning for a "better" access point - those background scans cause the classic ping spike every 30-60 seconds. The connection drops for a few seconds while applying.' `
  -Apply { Set-NicMode $RoamKeys 'roam' 'min' } -Revert { Restore-NicMode $RoamKeys 'roam' } -Check { Test-NicMode $RoamKeys 'min' }

T -Id 'nic-flowctl' -Name 'Disable Ethernet Flow Control' -Cat 'Network & Ping' -Risk 'Moderate' `
  -Desc 'Stops the network card and router from sending "pause" frames that briefly halt traffic. Can remove tiny delays on a busy LAN; on rare setups it causes more packet loss - turn it back off if your ping gets worse.' `
  -Apply { Set-NicMode $FlowKeys 'flow' 'zero' } -Revert { Restore-NicMode $FlowKeys 'flow' } -Check { Test-NicMode $FlowKeys 'zero' }

# ======================= INPUT =======================
$script:DXGLOBAL = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'

T -Id 'windowed-opt' -Name 'Optimizations for Windowed Games' -Cat 'Input' `
  -Desc 'Windows 11 feature: DirectX 10/11 games in borderless or windowed mode use the modern flip presentation model - lower input lag, close to exclusive fullscreen.' `
  -Apply {
    $cur = [string](Get-RegValue $DXGLOBAL 'DirectXUserGlobalSettings')
    $parts = @($cur -split ';' | Where-Object { $_ -and $_ -notmatch '^SwapEffectUpgradeEnable=' })
    Set-Reg $DXGLOBAL 'DirectXUserGlobalSettings' ((($parts + 'SwapEffectUpgradeEnable=1') -join ';') + ';') 'String'
  } -Revert { Restore-Reg $DXGLOBAL 'DirectXUserGlobalSettings' $null } `
  -Check { [string](Get-RegValue $DXGLOBAL 'DirectXUserGlobalSettings') -match 'SwapEffectUpgradeEnable=1' }

T -Id 'usb-device-power' -Name 'Disable Power Saving on USB & Input Devices' -Cat 'Input' `
  -Desc 'Turns off "Allow the computer to turn off this device to save power" for every USB controller, hub, mouse, keyboard and HID device - no more wake-up delay or dropped inputs.' `
  -Apply {
    $ids = @(Get-PnpDevice -PresentOnly -Class USB, HIDClass, Mouse, Keyboard -ErrorAction SilentlyContinue | ForEach-Object { $_.InstanceId })
    $n = 0
    foreach ($w in @(Get-CimInstance -Namespace root\wmi -ClassName MSPower_DeviceEnable -ErrorAction Stop)) {
        $inst = [string]$w.InstanceName
        if ($ids -notcontains ($inst -replace '_\d+$', '')) { continue }
        $n++
        if ($w.Enable) {
            $k = "usbpm_$inst"
            if (-not $State.misc.ContainsKey($k)) { $State.misc[$k] = $true }
            Set-CimInstance -InputObject $w -Property @{ Enable = $false } -ErrorAction SilentlyContinue
        }
    }
    if ($n -eq 0) { throw 'No USB device with a power-saving option was found.' }
  } -Revert {
    foreach ($w in @(Get-CimInstance -Namespace root\wmi -ClassName MSPower_DeviceEnable -ErrorAction SilentlyContinue)) {
        $k = "usbpm_$([string]$w.InstanceName)"
        if ($State.misc.ContainsKey($k)) { Set-CimInstance -InputObject $w -Property @{ Enable = $true } -ErrorAction SilentlyContinue; $State.misc.Remove($k) }
    }
  } -Check {
    $ids = @(Get-PnpDevice -PresentOnly -Class USB, HIDClass, Mouse, Keyboard -ErrorAction SilentlyContinue | ForEach-Object { $_.InstanceId })
    $any = $false
    foreach ($w in @(Get-CimInstance -Namespace root\wmi -ClassName MSPower_DeviceEnable -ErrorAction Stop)) {
        if ($ids -notcontains ([string]$w.InstanceName -replace '_\d+$', '')) { continue }
        $any = $true
        if ($w.Enable) { return $false }
    }
    $any
  }

T -Id 'hpet-default' -Name 'Use the Fast CPU Timer (no forced HPET)' -Cat 'Input' -Reboot `
  -Desc 'Some old tweak tools force Windows onto the slow HPET timer (useplatformclock), which adds latency and costs FPS. This removes that setting so Windows uses the fast built-in CPU timer. Shows as active when your PC is already correct.' `
  -Apply {
    $o = (bcdedit /enum '{current}') | Out-String
    if ($o -match 'useplatformclock\s+(\S+)') {
        $State.misc['hpet_was'] = $Matches[1]
        bcdedit /deletevalue '{current}' useplatformclock | Out-Null
    }
  } -Revert {
    if ($State.misc['hpet_was']) { bcdedit /set '{current}' useplatformclock ([string]$State.misc['hpet_was']) | Out-Null; $State.misc.Remove('hpet_was') }
  } -Check { ((bcdedit /enum '{current}') | Out-String) -notmatch 'useplatformclock' }

T -Id 'pointer-1to1' -Name 'Mouse Pointer Speed 6/11 (1:1)' -Cat 'Input' -Risk 'Moderate' `
  -Desc 'Sets the Windows pointer speed to the 6th notch, the only setting where one mouse count moves the cursor exactly one pixel. Games that do not use raw input then feel exactly like your mouse DPI. Your desktop cursor speed may change.' `
  -Reg (R 'HKCU:\Control Panel\Mouse' 'MouseSensitivity' '10' '10') `
  -Apply { [void][SBRaw]::SetMouseSpeed(10) } `
  -Revert {
    $b = $State.reg['HKCU:\Control Panel\Mouse|MouseSensitivity']
    $v = 10; if ($b -and $b.Exists) { try { $v = [int]$b.Value } catch { } }
    if ($v -lt 1 -or $v -gt 20) { $v = 10 }
    [void][SBRaw]::SetMouseSpeed($v)
  }

$script:TweakById = @{}
foreach ($t in $Tweaks) { $TweakById[$t.Id] = $t }
# Hardware rules. NeedRules: tweak cannot work on this PC (returns reason).
# FitRules: tweak works but is not a good idea on this PC (returns reason) - skipped by presets.
$script:NeedRules = @{
    'nic-rsc'      = { if (-not $HW.NicRsc) { 'network adapter does not support this' } }
    'nic-rss'      = { if (-not $HW.NicRss) { 'network adapter does not support this' } }
    'nic-buffers'  = { if (-not $HW.NicBuf) { 'network adapter has no buffer settings' } }
    'wifi-roam'    = { if (-not $HW.NicRoam) { 'no Wi-Fi adapter with a roaming setting' } }
    'nic-flowctl'  = { if (-not $HW.NicFlow) { 'network adapter has no flow control setting' } }
    'nic-eee'      = { if (-not $HW.NicEee) { 'network adapter has no power-saving options' } }
    'nic-lso'      = { if (-not $HW.NicLso) { 'network adapter has no Large Send Offload option' } }
    'windowed-opt' = { if ([int]$HW.Build -gt 0 -and [int]$HW.Build -lt 22621) { 'needs Windows 11 22H2 or newer' } }
    'gpu-msi'    = { if (-not $HW.IsNvidia) { 'needs an NVIDIA graphics card' } }
    'nvidia-tel' = { if (-not $HW.IsNvidia) { 'needs an NVIDIA graphics card' } }
    'retrim'     = { if (-not $HW.HasSSD) { 'no SSD detected' } }
    'trim'       = { if (-not $HW.HasSSD) { 'no SSD detected' } }
    'nic-power'  = { if (-not $HW.Nic) { 'no connected network adapter' } }
    'int-mod'    = { if (-not $HW.Nic) { 'no connected network adapter' } }
    'nagle'      = { if (-not $HW.Nic) { 'no connected network adapter' } }
    'dns-cf'     = { if (-not $HW.Nic) { 'no connected network adapter' } }
}
$script:FitRules = @{
    'print-spooler' = { if ($HW.HasPrinter) { 'a printer is installed' } }
    'ultimate-plan' = { if ($HW.IsLaptop) { 'laptop - drains the battery and adds heat' } }
    'core-parking'  = { if ($HW.IsLaptop) { 'laptop - drains the battery and adds heat' } }
    'usb-suspend'   = { if ($HW.IsLaptop) { 'laptop - costs battery life' } }
    'pcie-aspm'     = { if ($HW.IsLaptop) { 'laptop - costs battery life' } }
    'hibernation'   = { if ($HW.IsLaptop) { 'laptop - hibernation protects you on low battery' } }
    'timer-res'     = { if ($HW.IsLaptop) { 'laptop - costs battery life' } }
    'mem-compress'  = { if ($HW.RamGB -gt 0 -and $HW.RamGB -lt 16) { "only $($HW.RamGB) GB RAM - compression helps here" } }
    'paging-exec'   = { if ($HW.RamGB -gt 0 -and $HW.RamGB -lt 16) { "only $($HW.RamGB) GB RAM" } }
    'sysmain'       = { if (-not $HW.SysIsSSD) { 'Windows is on a hard drive - SysMain speeds that up' } }
    'search-index'  = { if (-not $HW.SysIsSSD) { 'Windows is on a hard drive' } }
}
function Update-Fit {
    foreach ($t in $Tweaks) {
        $t.NotAvail = $null; $t.Unfit = $null
        if ($NeedRules.ContainsKey($t.Id)) { try { $t.NotAvail = [string](& $NeedRules[$t.Id]) } catch { } }
        if ($FitRules.ContainsKey($t.Id)) { try { $t.Unfit = [string](& $FitRules[$t.Id]) } catch { } }
        if (-not $t.NotAvail) { $t.NotAvail = $null }
        if (-not $t.Unfit) { $t.Unfit = $null }
    }
}
function Test-Suitable($t) { (-not $t.NotAvail) -and (-not $t.Unfit) }

$script:FeaturedIds = @('ultimate-plan', 'hags', 'game-dvr', 'mmcss-games', 'power-throttling', 'net-throttle', 'mouse-accel', 'sysmain')

# ------------------------------------------------------------------ tweak engine
function Test-Tweak($t) {
    if ($t.Action) {
        if ($t.Check) { try { return [bool](& $t.Check) } catch { return $false } }
        return $false
    }
    $has = $false
    try {
        foreach ($r in $t.Reg) {
            if (-not $r) { continue }
            $has = $true
            $cur = Get-RegValue $r.P $r.N
            if ($r.Del) { if ($null -ne $cur) { return $false } }
            elseif ($null -eq $cur -or [string]$cur -ne [string]$r.V) { return $false }
        }
        foreach ($s in $t.Svc) {
            if (-not $s) { continue }
            $p = "HKLM:\SYSTEM\CurrentControlSet\Services\$s"
            if (Test-Path -LiteralPath $p) { $has = $true; if ((Get-RegValue $p 'Start') -ne 4) { return $false } }
        }
        foreach ($k in $t.Tasks) {
            if (-not $k) { continue }
            $has = $true
            if (-not (Test-TaskDisabled $k)) { return $false }
        }
        if ($t.Check) { $has = $true; if (-not (& $t.Check)) { return $false } }
    } catch { return $false }
    return $has
}

function Invoke-Tweak($t, [bool]$Enable) {
    $ErrorActionPreference = 'Stop'
    try {
        if ($Enable) {
            foreach ($r in $t.Reg) { if (-not $r) { continue }; if ($r.Del) { Remove-RegVal $r.P $r.N } else { Set-Reg $r.P $r.N $r.V $r.T } }
            foreach ($s in $t.Svc) { if ($s) { Disable-Svc $s } }
            foreach ($k in $t.Tasks) { if ($k) { Set-TaskState $k $false } }
            if ($t.Apply) { & $t.Apply | Out-Null }
        } else {
            if ($t.Revert) { & $t.Revert | Out-Null }
            foreach ($k in $t.Tasks) { if ($k) { Set-TaskState $k $true } }
            foreach ($s in $t.Svc) { if ($s) { Restore-Svc $s } }
            foreach ($r in $t.Reg) { if ($r) { Restore-Reg $r.P $r.N $r.D } }
        }
    } finally { Save-State }
}

# ------------------------------------------------------------------ restore point
$script:RPChecked = $false
$script:RPOk = $true
function New-RestorePoint {
    Set-Status 'Creating a System Restore point - this can take up to a minute...' 'busy'
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $old = Get-RegValue $k 'SystemRestorePointCreationFrequency'
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $k)) { New-Item -Path $k -Force | Out-Null }
        New-ItemProperty -LiteralPath $k -Name 'SystemRestorePointCreationFrequency' -Value 0 -PropertyType DWord -Force | Out-Null
        Checkpoint-Computer -Description 'Silvan Boost backup' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        $State.misc['LastRP'] = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        Save-State
        Write-Log 'System Restore point created.'
        return $true
    } catch {
        Write-Log "Restore point failed: $($_.Exception.Message)"
        return $false
    } finally {
        if ($null -eq $old) { Remove-ItemProperty -LiteralPath $k -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue }
        else { New-ItemProperty -LiteralPath $k -Name 'SystemRestorePointCreationFrequency' -Value $old -PropertyType DWord -Force | Out-Null }
        Update-BackupPage
    }
}
function Ensure-RestorePoint {
    if ($RPChecked) { return $RPOk }
    $script:RPChecked = $true
    Show-Overlay 'Creating a System Restore point before the first change...'
    $ok = New-RestorePoint
    Hide-Overlay
    if (-not $ok) {
        $r = Show-Msg ("Windows could not create a System Restore point (System Protection may be turned off).`n`n" +
            "Silvan Boost still saves every original value it changes, so you can revert from inside the app.`n`nContinue anyway?") `
            'Restore point' 'YesNo' 'Warning'
        $script:RPOk = ([string]$r -eq 'Yes')
    }
    return $RPOk
}

# ------------------------------------------------------------------ hardware scan
function Get-HW {
    $hw = @{}
    try {
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $hw.CpuName = (($cpu.Name -replace '\((R|TM)\)', '') -replace '\s+', ' ').Trim()
        $hw.CpuShort = ($hw.CpuName -replace '^Intel Core ', '' -replace ' Processor$', '')
        $hw.Cores = [int]$cpu.NumberOfCores
        $hw.Threads = [int]$cpu.NumberOfLogicalProcessors
        $pc = $hw.Threads - $hw.Cores; $ec = $hw.Cores - $pc
        if ($pc -gt 0 -and $ec -gt 0) { $hw.Topology = "$pc P-cores + $ec E-cores" } else { $hw.Topology = "$($hw.Cores) cores" }
        $hw.CpuBase = '{0:0.0} GHz' -f ($cpu.MaxClockSpeed / 1000)
        if ($cpu.L3CacheSize) { $hw.L3 = '{0} MB' -f [math]::Round($cpu.L3CacheSize / 1024) }
        try {
            $b = (Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -ErrorAction Stop).'Update Revision'
            if ($b -is [byte[]] -and $b.Length -ge 8) { $hw.Microcode = [BitConverter]::ToUInt32($b, 4) }
        } catch { }
    } catch { }

    try {
        $vc = @(Get-CimInstance Win32_VideoController)
        $g = $vc | Where-Object { $_.Name -match 'NVIDIA' } | Select-Object -First 1
        if (-not $g) { $g = $vc | Where-Object { $_.Name -match 'AMD|Radeon|Arc' } | Select-Object -First 1 }
        if (-not $g) { $g = $vc | Select-Object -First 1 }
        $hw.GpuName = [string]$g.Name
        $hw.GpuShort = ($hw.GpuName -replace '^NVIDIA GeForce ', '')
        $hw.GpuDriver = [string]$g.DriverVersion
        try { if ($g.DriverDate) { $hw.GpuDriverDate = [datetime]$g.DriverDate } } catch { }
    } catch { }

    $smi = $null
    $cmd = Get-Command nvidia-smi.exe -ErrorAction SilentlyContinue
    if ($cmd) { $smi = $cmd.Source }
    elseif (Test-Path 'C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe') { $smi = 'C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe' }
    $hw.Smi = $smi
    if ($smi) {
        try {
            $l = (& $smi --query-gpu=name,driver_version,memory.total,pcie.link.gen.max,pcie.link.width.max --format=csv,noheader,nounits | Select-Object -First 1) -split ','
            if ($l.Count -ge 5) {
                $hw.GpuName = $l[0].Trim(); $hw.GpuShort = ($hw.GpuName -replace '^NVIDIA GeForce ', '')
                $hw.GpuDriver = $l[1].Trim()
                $hw.VramGB = [math]::Round([double]$l[2].Trim() / 1024)
                $hw.Pcie = "Gen $($l[3].Trim()) x$($l[4].Trim())"
            }
            $q = (& $smi -q -d MEMORY) | Out-String
            $m = [regex]::Match($q, 'BAR1 Memory Usage\s*[\r\n]+\s*Total\s*:\s*(\d+)\s*MiB')
            if ($m.Success) { $hw.Bar1 = [int]$m.Groups[1].Value }
        } catch { }
    }

    try {
        $mods = @(Get-CimInstance Win32_PhysicalMemory)
        $hw.RamGB = [math]::Round((($mods | Measure-Object Capacity -Sum).Sum) / 1GB)
        $hw.RamMods = $mods.Count
        $hw.RamModSize = [math]::Round(([double]$mods[0].Capacity) / 1GB)
        $hw.RamRated = [int](($mods | Measure-Object Speed -Maximum).Maximum)
        $hw.RamConf = [int](($mods | Measure-Object ConfiguredClockSpeed -Minimum).Minimum)
        switch ([int]$mods[0].SMBIOSMemoryType) { 34 { $hw.RamType = 'DDR5' } 26 { $hw.RamType = 'DDR4' } default { $hw.RamType = 'RAM' } }
        $hw.RamMfr = ([string]$mods[0].Manufacturer).Trim()
        $hw.RamPart = ([string]$mods[0].PartNumber).Trim()
    } catch { }

    try {
        $hw.Disks = @(Get-PhysicalDisk -ErrorAction Stop | Sort-Object DeviceId | ForEach-Object {
            @{ Name = ([string]$_.FriendlyName).Trim(); Type = [string]$_.MediaType; Bus = [string]$_.BusType; SizeGB = [math]::Round($_.Size / 1GB) } })
    } catch { $hw.Disks = @() }
    try {
        $v = Get-Volume -DriveLetter $env:SystemDrive[0] -ErrorAction Stop
        $hw.SysFreeGB = [math]::Round($v.SizeRemaining / 1GB)
        $hw.SysSizeGB = [math]::Round($v.Size / 1GB)
    } catch { }

    try { $r = [SBNative]::Refresh(); $hw.RefCur = $r[0]; $hw.RefMax = $r[1]; $hw.ResW = $r[2]; $hw.ResH = $r[3] } catch { }

    try {
        $bb = Get-CimInstance Win32_BaseBoard
        $hw.Board = ("{0} {1}" -f $bb.Manufacturer, $bb.Product).Trim()
        $bios = Get-CimInstance Win32_BIOS
        $hw.Bios = [string]$bios.SMBIOSBIOSVersion
        if ($bios.ReleaseDate) { $hw.BiosDate = $bios.ReleaseDate.ToString('yyyy-MM-dd') }
    } catch { }

    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $hw.OS = ([string]$os.Caption -replace '^Microsoft ', '')
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $hw.OSVer = [string]$cv.DisplayVersion
        $hw.OSBuild = "$($cv.CurrentBuild).$($cv.UBR)"
        $hw.Build = [int]$cv.CurrentBuild
    } catch { }

    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $hw.Vbs = [int]$dg.VirtualizationBasedSecurityStatus
        $hw.Hvci = (@($dg.SecurityServicesRunning) -contains 2)
    } catch { $hw.Vbs = -1 }

    try {
        $n = Get-UpNics | Select-Object -First 1
        if ($n) { $hw.Nic = [string]$n.InterfaceDescription; $hw.NicSpeed = [string]$n.LinkSpeed; $hw.NicName = [string]$n.Name }
    } catch { }

    $hw.IsNvidia = ([string]$hw.GpuName -match 'NVIDIA')
    $hw.IsIntelCpu = ([string]$hw.CpuName -match 'Intel')
    $hw.IsLaptop = $false
    try {
        $ch = @((Get-CimInstance Win32_SystemEnclosure).ChassisTypes)
        if (@($ch | Where-Object { @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32) -contains [int]$_ }).Count -gt 0) { $hw.IsLaptop = $true }
        if (@(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue).Count -gt 0) { $hw.IsLaptop = $true }
    } catch { }
    $hw.HasSSD = (@($hw.Disks | Where-Object { $_.Type -eq 'SSD' -or $_.Bus -eq 'NVMe' }).Count -gt 0)
    $hw.SysIsSSD = $hw.HasSSD
    try {
        $dn = (Get-Partition -DriveLetter $env:SystemDrive[0] -ErrorAction Stop).DiskNumber
        $pd = Get-PhysicalDisk -ErrorAction Stop | Where-Object { [string]$_.DeviceId -eq [string]$dn } | Select-Object -First 1
        if ($pd) { $hw.SysIsSSD = ([string]$pd.MediaType -eq 'SSD' -or [string]$pd.BusType -eq 'NVMe') }
    } catch { }
    $hw.NicEee = $false; $hw.NicLso = $false; $hw.NicBuf = $false; $hw.NicRoam = $false; $hw.NicFlow = $false; $hw.NicRsc = $false; $hw.NicRss = $false
    try {
        $hw.NicBuf = Test-NicHas $BufKeys 'max'; $hw.NicRoam = Test-NicHas $RoamKeys 'min'; $hw.NicFlow = Test-NicHas $FlowKeys 'zero'
        foreach ($a in Get-UpNics) {
            if (Get-NetAdapterRsc -Name $a.Name -ErrorAction SilentlyContinue) { $hw.NicRsc = $true }
            if (Get-NetAdapterRss -Name $a.Name -ErrorAction SilentlyContinue) { $hw.NicRss = $true }
        }
        foreach ($a in Get-UpNics) {
            if (@(Get-NicProps $a $EeeKeys).Count -gt 0) { $hw.NicEee = $true }
            if (@(Get-NicProps $a $LsoKeys).Count -gt 0) { $hw.NicLso = $true }
        }
    } catch { }
    $hw.HasPrinter = $false
    try { $hw.HasPrinter = (@(Get-Printer -ErrorAction Stop | Where-Object { $_.Name -notmatch 'PDF|XPS|OneNote|Fax' }).Count -gt 0) } catch { }
    $hw.Plan = Get-ActiveSchemeName
    $hw.GameMode = ((Get-RegValue $GBAR 'AutoGameModeEnabled') -ne 0)
    $hw.Hags = ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode') -eq 2)
    $hw
}

function Get-Recs($hw) {
    $r = New-Object System.Collections.ArrayList
    function AddRec($s, $title, $text) { [void]$r.Add(@{ S = $s; T = $title; X = $text }) }

    if ($hw.RamConf -gt 0) {
        if (($hw.RamRated -gt 0 -and $hw.RamConf -lt $hw.RamRated) -or ($hw.RamType -eq 'DDR5' -and $hw.RamConf -le 4800)) {
            $prof = 'XMP'; if (-not $hw.IsIntelCpu) { $prof = 'EXPO / DOCP' }
            AddRec 'warn' "Memory may not be running at its rated speed ($prof off)" ("Your $($hw.RamType) runs at $($hw.RamConf) MT/s. Most gaming RAM kits are rated higher (check the sticker or box) - enter BIOS and enable $prof. This is often worth 5-15% FPS in CPU-heavy games and is the biggest free upgrade.")
        } else {
            AddRec 'ok' 'Memory runs at full speed' ("$($hw.RamConf) MT/s $($hw.RamType) - XMP is active.")
        }
        if ($hw.RamMods -eq 1) { AddRec 'warn' 'Single-channel memory' 'Only one RAM stick detected. Two sticks (dual channel) can give a large boost in CPU-bound games.' }
        elseif ($hw.RamMods -ge 4 -and $hw.RamType -eq 'DDR5') { AddRec 'info' 'Four DDR5 sticks installed' 'Four DDR5 DIMMs are harder to run at full XMP speed. If you get crashes after enabling XMP, test with two sticks.' }
    }

    if ($hw.RefCur -gt 0) {
        if ($hw.RefMax -gt $hw.RefCur) {
            AddRec 'warn' 'Monitor is not using its highest refresh rate' ("Running at $($hw.RefCur) Hz but $($hw.RefMax) Hz is available. Settings > System > Display > Advanced display > Choose a refresh rate. Also check that you use DisplayPort or a high-speed HDMI cable.")
        } else {
            AddRec 'ok' 'Monitor uses its maximum refresh rate' ("$($hw.ResW) x $($hw.ResH) at $($hw.RefCur) Hz.")
        }
    }

    if ($hw.Bar1 -gt 0) {
        if ($hw.Bar1 -gt 1024) { AddRec 'ok' 'Resizable BAR is enabled' 'The CPU can access all of the graphics card memory at once.' }
        else { AddRec 'warn' 'Resizable BAR is off' 'Enable "Above 4G Decoding" and "Re-Size BAR Support" in BIOS (CSM must be off). Some older RTX 30 cards need a vBIOS update from the card maker first. Many games gain a few percent.' }
    }

    if ($hw.CpuName -match 'i[3579]-1[34]\d{3}' -and $hw.Microcode) {
        $mc = '0x{0:X}' -f $hw.Microcode
        if ($hw.Microcode -lt 0x12B) {
            AddRec 'warn' 'CPU microcode is outdated - update your BIOS' ("Your CPU reports microcode $mc. Intel 13th/14th-gen CPUs need 0x12B or newer to prevent the known Vmin-shift instability and degradation. Install the latest BIOS from your motherboard maker and keep Intel Default Settings.")
        } else {
            AddRec 'ok' 'CPU microcode includes Intel''s stability fix' ("Microcode $mc - the 14th-gen Vmin-shift fix is installed.")
        }
    }

    if ($hw.Vbs -eq 2) { AddRec 'info' 'Virtualization-Based Security is running' 'VBS / Memory Integrity can cost a few percent in some games. It is a real security feature - see the Advanced tweak "Disable Memory Integrity" if you want to trade it off.' }

    if ($hw.SysSizeGB -gt 0) {
        $pct = $hw.SysFreeGB / $hw.SysSizeGB * 100
        if ($pct -lt 15) { AddRec 'warn' 'System drive is almost full' ("Only $($hw.SysFreeGB) GB free on $($env:SystemDrive). SSDs slow down when nearly full - keep at least 15% free.") }
        else { AddRec 'ok' 'Enough free SSD space' ("$($hw.SysFreeGB) GB free of $($hw.SysSizeGB) GB on $($env:SystemDrive).") }
    }

    if ($hw.IsLaptop) { AddRec 'info' 'Laptop detected' 'Power-hungry tweaks are marked "not recommended" and skipped by the presets. Plug in your charger while gaming and use your laptop maker''s performance mode.' }
    if (-not $hw.SysIsSSD) { AddRec 'warn' 'Windows is installed on a hard drive' 'Moving Windows and your games to an SSD is the biggest upgrade for loading times and stutter.' }
    if (-not $hw.Hags) { AddRec 'info' 'Hardware-accelerated GPU scheduling is off' 'Turn on the "Hardware-Accelerated GPU Scheduling" optimization and restart.' }

    if ($hw.GpuDriverDate) {
        $age = ((Get-Date) - $hw.GpuDriverDate).TotalDays
        $ds = $hw.GpuDriverDate.ToString('yyyy-MM-dd')
        $how = 'Get the newest driver from your graphics card or laptop maker.'
        if ($hw.GpuName -match 'NVIDIA') { $how = 'Open the NVIDIA App, go to Drivers and click Download. If you had crashes, choose "Clean install".' }
        elseif ($hw.GpuName -match 'AMD|Radeon') { $how = 'Open AMD Software: Adrenalin Edition and click Check for updates.' }
        if ($age -gt 120) { AddRec 'warn' 'Update your graphics driver' (("Driver $($hw.GpuDriver) ($ds): {0:0} months old - newer drivers often bring FPS fixes for new games. " -f ($age / 30.4)) + $how) }
        elseif ($age -ge 0) { AddRec 'ok' 'Graphics driver is up to date' "Driver $($hw.GpuDriver) from $ds." }
    }
    if ($hw.GpuName -match 'AMD|Radeon') {
        AddRec 'info' ("AMD driver " + $hw.GpuDriver) 'Keep it current via AMD Software: Adrenalin Edition, and turn on Radeon Anti-Lag in games for lower input latency.'
    }
    if ($hw.GpuName -match 'NVIDIA') {
        AddRec 'info' ("NVIDIA driver " + $hw.GpuDriver) 'Keep it current via the NVIDIA App. In NVIDIA Control Panel set Power management mode to "Prefer maximum performance", and turn on NVIDIA Reflex in games that support it - the biggest single latency win.'
    }
    $r
}

# ------------------------------------------------------------------ XAML
$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Silvan Boost - FPS Optimizer" Width="1400" Height="820" MinWidth="1120" MinHeight="680"
        WindowStartupLocation="CenterScreen" WindowStyle="None" ResizeMode="CanResize"
        Background="#0A0F1C" Foreground="#E8ECF5" FontFamily="Segoe UI" FontSize="13"
        UseLayoutRounding="True" SnapsToDevicePixels="True">
  <WindowChrome.WindowChrome>
    <WindowChrome CaptionHeight="44" ResizeBorderThickness="6" CornerRadius="0" GlassFrameThickness="0" UseAeroCaptionButtons="False"/>
  </WindowChrome.WindowChrome>

  <Window.Resources>
    <FontFamily x:Key="IconFont">Segoe Fluent Icons, Segoe MDL2 Assets</FontFamily>

    <Style x:Key="Icon" TargetType="TextBlock">
      <Setter Property="FontFamily" Value="{StaticResource IconFont}"/>
      <Setter Property="FontSize" Value="18"/>
      <Setter Property="HorizontalAlignment" Value="Center"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="H1" TargetType="TextBlock">
      <Setter Property="FontFamily" Value="Segoe UI Variable Display, Segoe UI"/>
      <Setter Property="FontSize" Value="27"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="Sub" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#9AA5BF"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Margin" Value="0,4,0,0"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
    <Style x:Key="Label" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#9AA5BF"/>
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="SectionTitle" TargetType="TextBlock">
      <Setter Property="FontSize" Value="16"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>

    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="#111A2E"/>
      <Setter Property="BorderBrush" Value="#1E2A45"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="14"/>
      <Setter Property="Padding" Value="18"/>
    </Style>

    <Style x:Key="NavBtn" TargetType="RadioButton">
      <Setter Property="Foreground" Value="#8C96AD"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="GroupName" Value="nav"/>
      <Setter Property="Margin" Value="10,1"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Grid Background="Transparent">
              <Border x:Name="Bd" CornerRadius="9" Background="Transparent" Padding="12,8">
                <ContentPresenter VerticalAlignment="Center"/>
              </Border>
              <Border x:Name="Ind" Width="3" Height="18" CornerRadius="2" HorizontalAlignment="Left" Background="#FF8A1F" Visibility="Hidden"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#16213A"/>
                <Setter Property="Foreground" Value="#D5DCEB"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#24FF8A1F"/>
                <Setter TargetName="Ind" Property="Visibility" Value="Visible"/>
                <Setter Property="Foreground" Value="#FFA24A"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="NavIcon" TargetType="TextBlock">
      <Setter Property="FontFamily" Value="{StaticResource IconFont}"/>
      <Setter Property="FontSize" Value="16"/>
      <Setter Property="Width" Value="22"/>
      <Setter Property="TextAlignment" Value="Center"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="NavText" TargetType="TextBlock">
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Margin" Value="11,0,0,0"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="NavHeader" TargetType="TextBlock">
      <Setter Property="FontSize" Value="10.5"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Foreground" Value="#56617C"/>
      <Setter Property="Margin" Value="24,16,0,6"/>
    </Style>
    <Style x:Key="NavSub" TargetType="RadioButton">
      <Setter Property="Foreground" Value="#9AA5BF"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="GroupName" Value="nav"/>
      <Setter Property="Margin" Value="0,1,10,1"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Grid Height="32" Background="Transparent">
              <Border x:Name="Bd" CornerRadius="8" Background="Transparent" Margin="6,0,0,0" Padding="12,0">
                <ContentPresenter VerticalAlignment="Center"/>
              </Border>
              <Border x:Name="Ind" Width="3" Height="16" CornerRadius="2" HorizontalAlignment="Left" Margin="-2,0,0,0" Background="#FF8A1F" Visibility="Hidden"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#141E36"/>
                <Setter Property="Foreground" Value="#E8ECF5"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#1AFF8A1F"/>
                <Setter TargetName="Ind" Property="Visibility" Value="Visible"/>
                <Setter Property="Foreground" Value="#FFA24A"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="CatBtn" TargetType="Button">
      <Setter Property="Foreground" Value="#B7C0D6"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Margin" Value="10,1"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" CornerRadius="8" Background="Transparent" Padding="12,9">
              <ContentPresenter HorizontalAlignment="Stretch" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#141E36"/>
                <Setter Property="Foreground" Value="#E8ECF5"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="PresetCard" TargetType="RadioButton">
      <Setter Property="Foreground" Value="#E8ECF5"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="GroupName" Value="qb"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="Bd" CornerRadius="14" Background="#111A2E" BorderBrush="#1E2A45" BorderThickness="1" Padding="22,20">
              <DockPanel>
                <Grid DockPanel.Dock="Right" Width="20" Height="20" VerticalAlignment="Top" Margin="12,0,0,0">
                  <Ellipse x:Name="Ring" Stroke="#2A3858" StrokeThickness="2"/>
                  <Ellipse x:Name="Dot" Width="10" Height="10" Fill="#FF8A1F" Visibility="Hidden"/>
                </Grid>
                <ContentPresenter/>
              </DockPanel>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#16213A"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="#FF8A1F"/>
                <Setter TargetName="Bd" Property="BorderThickness" Value="2"/>
                <Setter TargetName="Bd" Property="Padding" Value="21,19"/>
                <Setter TargetName="Ring" Property="Stroke" Value="#FF8A1F"/>
                <Setter TargetName="Dot" Property="Visibility" Value="Visible"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="TopChip" TargetType="Button">
      <Setter Property="Foreground" Value="#C3CBDD"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Height" Value="28"/>
      <Setter Property="MinWidth" Value="28"/>
      <Setter Property="FontSize" Value="12.5"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="WindowChrome.IsHitTestVisibleInChrome" Value="True"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" CornerRadius="14" Background="Transparent" BorderBrush="#22304D" BorderThickness="1" Padding="9,0">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="#FF8A1F"/>
                <Setter Property="Foreground" Value="#FFB36B"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="LangCard" TargetType="RadioButton">
      <Setter Property="Foreground" Value="#E8ECF5"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="GroupName" Value="tourlang"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="Bd" CornerRadius="12" Background="#0E1628" BorderBrush="#26334F" BorderThickness="1.5" Padding="16,14">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#34446A"/></Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="#FF8A1F"/>
                <Setter TargetName="Bd" Property="Background" Value="#1AFF8A1F"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="OptRow" TargetType="RadioButton">
      <Setter Property="Foreground" Value="#E8ECF5"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="GroupName" Value="act"/>
      <Setter Property="Margin" Value="0,0,0,6"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="Bd" CornerRadius="10" Background="Transparent" BorderBrush="#1E2A45" BorderThickness="1" Padding="12,8">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#141E36"/></Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="#FF8A1F"/>
                <Setter TargetName="Bd" Property="Background" Value="#14FF8A1F"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.42"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="ListRow" TargetType="RadioButton">
      <Setter Property="Foreground" Value="#E8ECF5"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Margin" Value="0,0,0,4"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Grid>
              <Border x:Name="Bd" CornerRadius="10" Background="Transparent" Padding="12,9">
                <ContentPresenter VerticalAlignment="Center"/>
              </Border>
              <Border x:Name="Ind" Width="3" Height="18" CornerRadius="2" HorizontalAlignment="Left" Background="#FF8A1F" Visibility="Hidden"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#141E36"/></Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#1AFF8A1F"/>
                <Setter TargetName="Ind" Property="Visibility" Value="Visible"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Field" TargetType="TextBox">
      <Setter Property="Foreground" Value="#E8ECF5"/>
      <Setter Property="CaretBrush" Value="#FF8A1F"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Bd" CornerRadius="8" Background="#0E1628" BorderBrush="#2A3858" BorderThickness="1" Padding="8,6">
              <ScrollViewer x:Name="PART_ContentHost"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#FF8A1F"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="HotSpot" TargetType="Button">
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Background" Value="#24304A"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" CornerRadius="{Binding Tag, RelativeSource={RelativeSource TemplatedParent}}" Background="{TemplateBinding Background}" BorderBrush="#3A4A6E" BorderThickness="1"/>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#FF8A1F"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Chip" TargetType="RadioButton">
      <Setter Property="Foreground" Value="#A9B3CC"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FontSize" Value="12.5"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="Bd" CornerRadius="9" Padding="13,6" Background="#111A2E" BorderBrush="#22304D" BorderThickness="1">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#16213A"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#26FF8A1F"/>
                <Setter TargetName="Bd" Property="BorderBrush" Value="#FF8A1F"/>
                <Setter Property="Foreground" Value="#FFB06A"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="PrimaryBtn" TargetType="Button">
      <Setter Property="Foreground" Value="#1A0E00"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Padding" Value="18,10"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" CornerRadius="10" Padding="{TemplateBinding Padding}">
              <Border.Background>
                <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                  <GradientStop Color="#FFB347" Offset="0"/>
                  <GradientStop Color="#FF7A00" Offset="1"/>
                </LinearGradientBrush>
              </Border.Background>
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.88"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.72"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="GhostBtn" TargetType="Button">
      <Setter Property="Foreground" Value="#E8ECF5"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Padding" Value="16,9"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" CornerRadius="10" Padding="{TemplateBinding Padding}" Background="#16213A" BorderBrush="#2A3858" BorderThickness="1">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#1B2642"/>
                <Setter TargetName="Bd" Property="BorderBrush" Value="#80FF8A1F"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.8"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="AuthField" TargetType="TextBox">
      <Setter Property="Foreground" Value="#E8ECF5"/>
      <Setter Property="CaretBrush" Value="#FF8A1F"/>
      <Setter Property="FontSize" Value="14.5"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Bd" CornerRadius="10" Background="#0E1628" BorderBrush="#2A3858" BorderThickness="1" Padding="11,9">
              <ScrollViewer x:Name="PART_ContentHost"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#3A4C72"/></Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#FF8A1F"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="AuthPass" TargetType="PasswordBox">
      <Setter Property="Foreground" Value="#E8ECF5"/>
      <Setter Property="CaretBrush" Value="#FF8A1F"/>
      <Setter Property="FontSize" Value="14.5"/>
      <Setter Property="PasswordChar" Value="&#x25CF;"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="PasswordBox">
            <Border x:Name="Bd" CornerRadius="10" Background="#0E1628" BorderBrush="#2A3858" BorderThickness="1" Padding="11,9">
              <ScrollViewer x:Name="PART_ContentHost"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#3A4C72"/></Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#FF8A1F"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="LinkBtn" TargetType="Button">
      <Setter Property="Foreground" Value="#FFB36B"/>
      <Setter Property="FontSize" Value="13.5"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="HorizontalAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="Transparent" Padding="6,4">
              <TextBlock x:Name="Tx" Text="{Binding Content, RelativeSource={RelativeSource TemplatedParent}}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Tx" Property="TextDecorations" Value="Underline"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="AuthLbl" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#7F8BA6"/>
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Margin" Value="0,14,0,6"/>
    </Style>
    <Style x:Key="AuthErr" TargetType="Border">
      <Setter Property="Background" Value="#1FF87171"/>
      <Setter Property="CornerRadius" Value="9"/>
      <Setter Property="Padding" Value="12,9"/>
      <Setter Property="Margin" Value="0,14,0,0"/>
      <Setter Property="Visibility" Value="Collapsed"/>
    </Style>

    <Style x:Key="SmallBtn" TargetType="Button">
      <Setter Property="Foreground" Value="#FFB06A"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" CornerRadius="8" Padding="14,5" Background="#1FFF8A1F" BorderBrush="#55FF8A1F" BorderThickness="1">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#33FF8A1F"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.75"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="TileBtn" TargetType="Button">
      <Setter Property="Foreground" Value="#E8ECF5"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" CornerRadius="12" Padding="10,14" Background="#111A2E" BorderBrush="#1E2A45" BorderThickness="1">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="#FF8A1F"/>
                <Setter TargetName="Bd" Property="Background" Value="#141F37"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.8"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="TitleBtn" TargetType="Button">
      <Setter Property="Foreground" Value="#9AA5BF"/>
      <Setter Property="WindowChrome.IsHitTestVisibleInChrome" Value="True"/>
      <Setter Property="FontFamily" Value="{StaticResource IconFont}"/>
      <Setter Property="FontSize" Value="10"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Width="46" Height="44" Background="Transparent">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#1B2642"/>
                <Setter Property="Foreground" Value="#E8ECF5"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="CloseBtn" TargetType="Button" BasedOn="{StaticResource TitleBtn}">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Width="46" Height="44" Background="Transparent">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#E81123"/>
                <Setter Property="Foreground" Value="#FFFFFF"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Toggle" TargetType="CheckBox">
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <Border x:Name="Track" Width="42" Height="23" CornerRadius="11.5" BorderThickness="1">
              <Border.Background><SolidColorBrush Color="#1A2540"/></Border.Background>
              <Border.BorderBrush><SolidColorBrush Color="#2A3858"/></Border.BorderBrush>
              <Ellipse x:Name="Knob" Width="15" Height="15" Margin="3,0" HorizontalAlignment="Left" VerticalAlignment="Center">
                <Ellipse.Fill><SolidColorBrush Color="#9AA5BF"/></Ellipse.Fill>
                <Ellipse.RenderTransform><TranslateTransform X="0"/></Ellipse.RenderTransform>
              </Ellipse>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Trigger.EnterActions>
                  <BeginStoryboard>
                    <Storyboard>
                      <DoubleAnimation Storyboard.TargetName="Knob" Storyboard.TargetProperty="(UIElement.RenderTransform).(TranslateTransform.X)" To="19" Duration="0:0:0.2">
                        <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut"/></DoubleAnimation.EasingFunction>
                      </DoubleAnimation>
                      <ColorAnimation Storyboard.TargetName="Track" Storyboard.TargetProperty="(Border.Background).(SolidColorBrush.Color)" To="#2ED47A" Duration="0:0:0.2"/>
                      <ColorAnimation Storyboard.TargetName="Track" Storyboard.TargetProperty="(Border.BorderBrush).(SolidColorBrush.Color)" To="#2ED47A" Duration="0:0:0.2"/>
                      <ColorAnimation Storyboard.TargetName="Knob" Storyboard.TargetProperty="(Shape.Fill).(SolidColorBrush.Color)" To="#06180E" Duration="0:0:0.2"/>
                    </Storyboard>
                  </BeginStoryboard>
                </Trigger.EnterActions>
                <Trigger.ExitActions>
                  <BeginStoryboard>
                    <Storyboard>
                      <DoubleAnimation Storyboard.TargetName="Knob" Storyboard.TargetProperty="(UIElement.RenderTransform).(TranslateTransform.X)" To="0" Duration="0:0:0.2">
                        <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut"/></DoubleAnimation.EasingFunction>
                      </DoubleAnimation>
                      <ColorAnimation Storyboard.TargetName="Track" Storyboard.TargetProperty="(Border.Background).(SolidColorBrush.Color)" To="#1A2540" Duration="0:0:0.2"/>
                      <ColorAnimation Storyboard.TargetName="Track" Storyboard.TargetProperty="(Border.BorderBrush).(SolidColorBrush.Color)" To="#2A3858" Duration="0:0:0.2"/>
                      <ColorAnimation Storyboard.TargetName="Knob" Storyboard.TargetProperty="(Shape.Fill).(SolidColorBrush.Color)" To="#9AA5BF" Duration="0:0:0.2"/>
                    </Storyboard>
                  </BeginStoryboard>
                </Trigger.ExitActions>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Track" Property="Opacity" Value="0.9"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Search" TargetType="TextBox">
      <Setter Property="Foreground" Value="#E8ECF5"/>
      <Setter Property="CaretBrush" Value="#FF8A1F"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Bd" CornerRadius="10" Background="#111A2E" BorderBrush="#22304D" BorderThickness="1">
              <Grid>
                <TextBlock Text="&#xE721;" FontFamily="{StaticResource IconFont}" FontSize="13" Foreground="#7F8BA6" Margin="12,0,0,0" VerticalAlignment="Center" HorizontalAlignment="Left"/>
                <TextBlock x:Name="Ph" Text="{Binding Tag, RelativeSource={RelativeSource TemplatedParent}}" Foreground="#5D6782" Margin="34,0,0,0" VerticalAlignment="Center" Visibility="Collapsed"/>
                <ScrollViewer x:Name="PART_ContentHost" Margin="32,0,8,0" VerticalAlignment="Center"/>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="Text" Value=""><Setter TargetName="Ph" Property="Visibility" Value="Visible"/></Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#FF8A1F"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="ToolTip">
      <Setter Property="Background" Value="#1A2440"/>
      <Setter Property="Foreground" Value="#E8ECF5"/>
      <Setter Property="BorderBrush" Value="#2A3656"/>
      <Setter Property="Padding" Value="10,7"/>
      <Setter Property="ContentTemplate">
        <Setter.Value>
          <DataTemplate><TextBlock Text="{Binding}" TextWrapping="Wrap" MaxWidth="320"/></DataTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="ScrollBar">
      <Setter Property="Width" Value="8"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollBar">
            <Track x:Name="PART_Track" IsDirectionReversed="True">
              <Track.Thumb>
                <Thumb>
                  <Thumb.Template>
                    <ControlTemplate TargetType="Thumb">
                      <Border CornerRadius="4" Background="#2A3656" Margin="1,2"/>
                    </ControlTemplate>
                  </Thumb.Template>
                </Thumb>
              </Track.Thumb>
            </Track>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Border x:Name="RootBorder" BorderBrush="#1A2440" BorderThickness="1" Background="#0A0F1C">
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="240"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <!-- Sidebar -->
      <Border Grid.Column="0" Background="#0C1324" BorderBrush="#18223A" BorderThickness="0,0,1,0">
        <DockPanel>
          <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="22,16,0,14">
            <Border Width="38" Height="38" CornerRadius="11">
              <Border.Background>
                <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                  <GradientStop Color="#FFB347" Offset="0"/>
                  <GradientStop Color="#FF6A00" Offset="1"/>
                </LinearGradientBrush>
              </Border.Background>
              <TextBlock Text="S" FontFamily="Segoe UI Variable Display, Segoe UI" FontWeight="Black" FontSize="21" Foreground="#0A0F1C" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="0,-2,0,0"/>
            </Border>
            <StackPanel Margin="11,0,0,0" VerticalAlignment="Center">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="SILVAN" FontWeight="Black" FontSize="14"/>
                <TextBlock Text="BOOST" FontWeight="Black" FontSize="14" Foreground="#FF8A1F" Margin="4,0,0,0"/>
              </StackPanel>
              <TextBlock x:Name="SideVer" Text="" FontSize="11" Foreground="#7F8BA6"/>
            </StackPanel>
          </StackPanel>
          <StackPanel DockPanel.Dock="Bottom" Margin="0,0,0,12">
              <Button x:Name="CatSys" Style="{StaticResource CatBtn}">
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <TextBlock Text="&#xE713;" Style="{StaticResource NavIcon}"/>
                  <TextBlock Grid.Column="1" Text="System" Style="{StaticResource NavText}"/>
                  <Ellipse x:Name="CatSysDot" Grid.Column="2" Width="6" Height="6" Fill="#FF8A1F" Margin="0,0,10,0" VerticalAlignment="Center" Visibility="Collapsed"/>
                  <TextBlock x:Name="CatSysChev" Grid.Column="3" Text="&#xE76C;" FontFamily="{StaticResource IconFont}" FontSize="10" VerticalAlignment="Center" RenderTransformOrigin="0.5,0.5">
                    <TextBlock.RenderTransform><RotateTransform Angle="0"/></TextBlock.RenderTransform>
                  </TextBlock>
                </Grid>
              </Button>
              <Border x:Name="SubSys" Height="0" Opacity="0" ClipToBounds="True">
                <Grid>
                  <Border Width="1" Background="#22304D" HorizontalAlignment="Left" Margin="33,4,0,6"/>
                  <StackPanel x:Name="SubSysItems" Margin="34,2,0,4">
                    <RadioButton x:Name="NavBackup" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="Backup &amp; Restore" VerticalAlignment="Center"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="NavAbout" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="Updates &amp; About" VerticalAlignment="Center"/>
                        <Ellipse x:Name="UpdDot" Width="7" Height="7" Fill="#FF8A1F" Margin="8,0,0,0" VerticalAlignment="Center" Visibility="Collapsed"/>
                      </StackPanel>
                    </RadioButton>
                  </StackPanel>
                </Grid>
              </Border>
              <Border x:Name="UserCardBox" Margin="12,10,12,0" Padding="10" CornerRadius="12" Background="#111A2E" BorderBrush="#1E2A45" BorderThickness="1" Cursor="Hand" ToolTip="Account">
                <DockPanel>
                  <Grid DockPanel.Dock="Left" Width="38" Height="38" VerticalAlignment="Center">
                    <Border CornerRadius="19" Background="#29FF8A1F" BorderBrush="#55FF8A1F" BorderThickness="1">
                      <TextBlock x:Name="UserInitial" Text="?" FontSize="15" FontWeight="SemiBold" Foreground="#FFA24A" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <Ellipse Width="11" Height="11" Fill="#2ED47A" Stroke="#111A2E" StrokeThickness="2" HorizontalAlignment="Right" VerticalAlignment="Bottom"/>
                  </Grid>
                  <StackPanel Margin="10,0,0,0" VerticalAlignment="Center">
                    <TextBlock x:Name="UserName" Text="" FontSize="13" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
                    <TextBlock x:Name="UserOs" Text="" FontSize="11" Foreground="#9AA5BF" TextWrapping="Wrap" Margin="0,1,0,0"/>
                    <TextBlock x:Name="UserPlan" Text="" FontSize="11" FontWeight="SemiBold" Foreground="#5BE39A" TextTrimming="CharacterEllipsis" Margin="0,2,0,0" Visibility="Collapsed"/>
                  </StackPanel>
                </DockPanel>
              </Border>
          </StackPanel>
          <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel Margin="0,4,0,8">
              <RadioButton x:Name="NavHome" Style="{StaticResource NavBtn}" IsChecked="True">
                <StackPanel Orientation="Horizontal">
                  <TextBlock Text="&#xE80F;" Style="{StaticResource NavIcon}"/>
                  <TextBlock Text="Dashboard" Style="{StaticResource NavText}"/>
                </StackPanel>
              </RadioButton>
              <RadioButton x:Name="NavScan" Style="{StaticResource NavBtn}">
                <StackPanel Orientation="Horizontal">
                  <TextBlock Text="&#xE9D9;" Style="{StaticResource NavIcon}"/>
                  <TextBlock Text="PC Scan" Style="{StaticResource NavText}"/>
                </StackPanel>
              </RadioButton>
              <Button x:Name="CatOpt" Style="{StaticResource CatBtn}">
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <TextBlock Text="&#xEC4A;" Style="{StaticResource NavIcon}"/>
                  <TextBlock Grid.Column="1" Text="Optimize" Style="{StaticResource NavText}"/>
                  <Ellipse x:Name="CatOptDot" Grid.Column="2" Width="6" Height="6" Fill="#FF8A1F" Margin="0,0,10,0" VerticalAlignment="Center" Visibility="Collapsed"/>
                  <TextBlock x:Name="CatOptChev" Grid.Column="3" Text="&#xE76C;" FontFamily="{StaticResource IconFont}" FontSize="10" VerticalAlignment="Center" RenderTransformOrigin="0.5,0.5">
                    <TextBlock.RenderTransform><RotateTransform Angle="0"/></TextBlock.RenderTransform>
                  </TextBlock>
                </Grid>
              </Button>
              <Border x:Name="SubOpt" Height="0" Opacity="0" ClipToBounds="True">
                <Grid>
                  <Border Width="1" Background="#22304D" HorizontalAlignment="Left" Margin="33,4,0,6"/>
                  <StackPanel x:Name="SubOptItems" Margin="34,2,0,4">
                    <RadioButton x:Name="NavQuick" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="Quick Boost" VerticalAlignment="Center"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="NavTweaks" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="All Optimizations" VerticalAlignment="Center"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="NavProc" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="Processes" VerticalAlignment="Center"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="NavApps" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="Apps" VerticalAlignment="Center"/>
                      </StackPanel>
                    </RadioButton>
                  </StackPanel>
                </Grid>
              </Border>
              <Button x:Name="CatGame" Style="{StaticResource CatBtn}">
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <TextBlock Text="&#xE7FC;" Style="{StaticResource NavIcon}"/>
                  <TextBlock Grid.Column="1" Text="Gaming" Style="{StaticResource NavText}"/>
                  <Ellipse x:Name="CatGameDot" Grid.Column="2" Width="6" Height="6" Fill="#FF8A1F" Margin="0,0,10,0" VerticalAlignment="Center" Visibility="Collapsed"/>
                  <TextBlock x:Name="CatGameChev" Grid.Column="3" Text="&#xE76C;" FontFamily="{StaticResource IconFont}" FontSize="10" VerticalAlignment="Center" RenderTransformOrigin="0.5,0.5">
                    <TextBlock.RenderTransform><RotateTransform Angle="0"/></TextBlock.RenderTransform>
                  </TextBlock>
                </Grid>
              </Button>
              <Border x:Name="SubGame" Height="0" Opacity="0" ClipToBounds="True">
                <Grid>
                  <Border Width="1" Background="#22304D" HorizontalAlignment="Left" Margin="33,4,0,6"/>
                  <StackPanel x:Name="SubGameItems" Margin="34,2,0,4">
                    <RadioButton x:Name="NavGames" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="Game Presets" VerticalAlignment="Center"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="NavPro" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="Pro Settings" VerticalAlignment="Center"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="NavLive" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="Live Monitor" VerticalAlignment="Center"/>
                        <Ellipse x:Name="LiveDot" Width="7" Height="7" Fill="#FF8A1F" Margin="8,0,0,0" VerticalAlignment="Center" Visibility="Collapsed"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="NavBench" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="Benchmark" VerticalAlignment="Center"/>
                        <Border CornerRadius="5" Background="#262ED47A" Padding="5,0" Margin="8,0,0,0" VerticalAlignment="Center"><TextBlock Text="NEW" FontSize="9" FontWeight="Bold" Foreground="#5BE39A"/></Border>
                      </StackPanel>
                    </RadioButton>
                  </StackPanel>
                </Grid>
              </Border>
              <Button x:Name="CatNet" Style="{StaticResource CatBtn}">
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <TextBlock Text="&#xE701;" Style="{StaticResource NavIcon}"/>
                  <TextBlock Grid.Column="1" Text="Network &amp; Input" Style="{StaticResource NavText}"/>
                  <Ellipse x:Name="CatNetDot" Grid.Column="2" Width="6" Height="6" Fill="#FF8A1F" Margin="0,0,10,0" VerticalAlignment="Center" Visibility="Collapsed"/>
                  <TextBlock x:Name="CatNetChev" Grid.Column="3" Text="&#xE76C;" FontFamily="{StaticResource IconFont}" FontSize="10" VerticalAlignment="Center" RenderTransformOrigin="0.5,0.5">
                    <TextBlock.RenderTransform><RotateTransform Angle="0"/></TextBlock.RenderTransform>
                  </TextBlock>
                </Grid>
              </Button>
              <Border x:Name="SubNet" Height="0" Opacity="0" ClipToBounds="True">
                <Grid>
                  <Border Width="1" Background="#22304D" HorizontalAlignment="Left" Margin="33,4,0,6"/>
                  <StackPanel x:Name="SubNetItems" Margin="34,2,0,4">
                    <RadioButton x:Name="NavPing" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="Ping Booster" VerticalAlignment="Center"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="NavInput" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="Input Lag" VerticalAlignment="Center"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="NavMacros" Style="{StaticResource NavSub}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="Macros" VerticalAlignment="Center"/>
                        <Border CornerRadius="5" Background="#262ED47A" Padding="5,0" Margin="8,0,0,0" VerticalAlignment="Center"><TextBlock Text="NEW" FontSize="9" FontWeight="Bold" Foreground="#5BE39A"/></Border>
                      </StackPanel>
                    </RadioButton>
                  </StackPanel>
                </Grid>
              </Border>
            </StackPanel>
          </ScrollViewer>
        </DockPanel>
      </Border>

      <Grid Grid.Column="1">
        <Grid.RowDefinitions>
          <RowDefinition Height="44"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="38"/>
        </Grid.RowDefinitions>

        <!-- Title bar -->
        <Grid Grid.Row="0">
          <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="36,0,0,0">
            <TextBlock x:Name="CrumbCat" Text="" FontSize="12.5" Foreground="#7F8BA6"/>
            <TextBlock x:Name="CrumbSep" Text="" FontSize="12.5" Foreground="#4A5675"/>
            <TextBlock x:Name="CrumbPage" Text="Dashboard" FontSize="12.5" FontWeight="SemiBold" Foreground="#E8ECF5"/>
            <Border Background="#16213A" CornerRadius="6" Padding="8,2" Margin="16,0,0,0" VerticalAlignment="Center">
              <TextBlock x:Name="TitleSpec" Text="FPS Optimizer" FontSize="11" Foreground="#9AA5BF"/>
            </Border>
          </StackPanel>
          <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="BtnLang" Style="{StaticResource TopChip}" Margin="0,0,8,0" VerticalAlignment="Center" ToolTip="Change language">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="&#xE774;" FontFamily="{StaticResource IconFont}" FontSize="12" VerticalAlignment="Center"/>
                <TextBlock x:Name="LangCode" Text="EN" FontSize="11.5" Margin="6,0,0,0" VerticalAlignment="Center"/>
              </StackPanel>
            </Button>
            <Button x:Name="BtnHelp" Style="{StaticResource TopChip}" Content="?" Width="28" Padding="0" Margin="0,0,14,0" VerticalAlignment="Center" ToolTip="Help: show the tour"/>
            <Button x:Name="BtnMin" Style="{StaticResource TitleBtn}" Content="&#xE921;"/>
            <Button x:Name="BtnMax" Style="{StaticResource TitleBtn}" Content="&#xE922;"/>
            <Button x:Name="BtnClose" Style="{StaticResource CloseBtn}" Content="&#xE8BB;"/>
          </StackPanel>
        </Grid>

        <!-- Pages -->
        <Grid Grid.Row="1">

          <!-- HOME -->
          <ScrollViewer x:Name="PageHome" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel Margin="36,10,36,28" MaxWidth="1120" HorizontalAlignment="Stretch">
              <TextBlock x:Name="HomeGreet" Text="Welcome back" Style="{StaticResource H1}"/>
              <TextBlock x:Name="HomeSub" Text="Scanning your PC..." Style="{StaticResource Sub}"/>

              <Border x:Name="HomeHero" Style="{StaticResource Card}" Margin="0,22,0,0" Padding="30,28">
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>
                  <Grid Width="184" Height="184" Margin="10">
                    <Ellipse Margin="-10" Stroke="#2A3858" StrokeThickness="2" StrokeDashArray="0.4 3.2" Opacity="0.8"/>
                    <Ellipse Stroke="#1A2540" StrokeThickness="12"/>
                    <Path x:Name="HeroArc" Stroke="#FF8A1F" StrokeThickness="12" StrokeStartLineCap="Round" StrokeEndLineCap="Round"/>
                    <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                      <TextBlock x:Name="StatScore" Text="0%" FontSize="40" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" HorizontalAlignment="Center"/>
                      <TextBlock Text="optimized" FontSize="12" Foreground="#9AA5BF" HorizontalAlignment="Center"/>
                    </StackPanel>
                  </Grid>
                  <StackPanel Grid.Column="1" Margin="40,0,0,0" VerticalAlignment="Center">
                    <Border HorizontalAlignment="Left" CornerRadius="11" Padding="10,3" Background="#1F2ED47A">
                      <StackPanel Orientation="Horizontal">
                        <Ellipse Width="7" Height="7" Fill="#2ED47A" VerticalAlignment="Center" Margin="0,0,7,0"/>
                        <TextBlock x:Name="StatActive" Text="0" FontSize="12" FontWeight="SemiBold" Foreground="#5BE39A"/>
                        <TextBlock Text=" optimizations active" FontSize="12" Foreground="#5BE39A"/>
                      </StackPanel>
                    </Border>
                    <TextBlock x:Name="HeroTitle" Text="Checking your PC..." FontSize="25" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" Margin="0,14,0,0" TextWrapping="Wrap"/>
                    <TextBlock x:Name="HeroText" Text="" Style="{StaticResource Sub}" FontSize="13.5" Margin="0,6,0,0"/>
                    <StackPanel Orientation="Horizontal" Margin="0,20,0,0">
                      <Button x:Name="BtnQuickBoost" Style="{StaticResource PrimaryBtn}" Padding="22,11">
                        <StackPanel Orientation="Horizontal">
                          <TextBlock Text="&#xE945;" FontFamily="{StaticResource IconFont}" FontSize="14" VerticalAlignment="Center" Margin="0,0,8,0"/>
                          <TextBlock Text="Quick Boost" VerticalAlignment="Center"/>
                        </StackPanel>
                      </Button>
                      <Button x:Name="BtnViewTweaks" Style="{StaticResource GhostBtn}" Content="All optimizations" Margin="10,0,0,0"/>
                    </StackPanel>
                    <Border Height="4" Visibility="Collapsed"><Border x:Name="ScoreBar" HorizontalAlignment="Left" Width="0"/></Border>
                  </StackPanel>
                </Grid>
              </Border>

              <StackPanel Orientation="Horizontal" Margin="2,28,0,12">
                <TextBlock Text="Right now" Style="{StaticResource SectionTitle}"/>
                <Border CornerRadius="9" Padding="8,1" Background="#1F2ED47A" Margin="10,0,0,0" VerticalAlignment="Center">
                  <StackPanel Orientation="Horizontal">
                    <Ellipse x:Name="LivePulse" Width="6" Height="6" Fill="#2ED47A" Margin="0,0,5,0" VerticalAlignment="Center"/>
                    <TextBlock Text="Live" FontSize="11" Foreground="#5BE39A"/>
                  </StackPanel>
                </Border>
              </StackPanel>
              <UniformGrid Columns="3" Margin="0,0,-12,0">
                <Border Style="{StaticResource Card}" Margin="0,0,12,0" Padding="18,16">
                  <StackPanel>
                    <DockPanel>
                      <TextBlock x:Name="CpuPct" DockPanel.Dock="Right" Text="-" FontSize="22" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI"/>
                      <StackPanel>
                        <TextBlock Text="CPU" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="CpuNameTxt" Text="" FontSize="11.5" Foreground="#7F8BA6" TextTrimming="CharacterEllipsis" Margin="0,3,10,0"/>
                      </StackPanel>
                    </DockPanel>
                    <Canvas x:Name="CpuSpark" Height="46" Margin="0,12,0,10" ClipToBounds="True">
                      <Polygon x:Name="CpuArea" Fill="#142ED47A"/>
                      <Polyline x:Name="CpuLine" Stroke="#2ED47A" StrokeThickness="1.75" StrokeLineJoin="Round"/>
                    </Canvas>
                    <TextBlock x:Name="CpuStat" Text="" FontSize="12" Foreground="#5BE39A"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,12,0" Padding="18,16">
                  <StackPanel>
                    <DockPanel>
                      <TextBlock x:Name="GpuPct" DockPanel.Dock="Right" Text="-" FontSize="22" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI"/>
                      <StackPanel>
                        <TextBlock Text="GPU" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="GpuInfo" Text="" FontSize="11.5" Foreground="#7F8BA6" TextTrimming="CharacterEllipsis" Margin="0,3,10,0"/>
                      </StackPanel>
                    </DockPanel>
                    <Canvas x:Name="GpuSpark" Height="46" Margin="0,12,0,10" ClipToBounds="True">
                      <Polygon x:Name="GpuArea" Fill="#142ED47A"/>
                      <Polyline x:Name="GpuLine" Stroke="#2ED47A" StrokeThickness="1.75" StrokeLineJoin="Round"/>
                    </Canvas>
                    <TextBlock x:Name="GpuStat" Text="" FontSize="12" Foreground="#5BE39A"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,12,0" Padding="18,16">
                  <StackPanel>
                    <DockPanel>
                      <TextBlock x:Name="RamPct" DockPanel.Dock="Right" Text="-" FontSize="22" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI"/>
                      <StackPanel>
                        <TextBlock Text="MEMORY" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="RamInfo" Text="" FontSize="11.5" Foreground="#7F8BA6" TextTrimming="CharacterEllipsis" Margin="0,3,10,0"/>
                      </StackPanel>
                    </DockPanel>
                    <Canvas x:Name="RamSpark" Height="46" Margin="0,12,0,10" ClipToBounds="True">
                      <Polygon x:Name="RamArea" Fill="#142ED47A"/>
                      <Polyline x:Name="RamLine" Stroke="#2ED47A" StrokeThickness="1.75" StrokeLineJoin="Round"/>
                    </Canvas>
                    <TextBlock x:Name="RamStat" Text="" FontSize="12" Foreground="#5BE39A"/>
                  </StackPanel>
                </Border>
              </UniformGrid>

              <Grid Margin="0,16,0,0">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="16"/>
                  <ColumnDefinition Width="330"/>
                </Grid.ColumnDefinitions>
                <Border Style="{StaticResource Card}" Padding="22,20">
                  <StackPanel>
                    <DockPanel>
                      <Button x:Name="BtnViewScan" DockPanel.Dock="Right" Style="{StaticResource SmallBtn}" Content="PC Scan"/>
                      <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                        <TextBlock Text="Next recommended step" Style="{StaticResource SectionTitle}"/>
                        <Border x:Name="RecBadge" CornerRadius="9" Padding="8,1" Background="#1FF59E0B" Margin="10,0,0,0" VerticalAlignment="Center" Visibility="Collapsed">
                          <StackPanel Orientation="Horizontal">
                            <TextBlock x:Name="StatRecs" Text="0" FontSize="11" FontWeight="SemiBold" Foreground="#FBBF24"/>
                            <TextBlock Text=" to check" FontSize="11" Foreground="#FBBF24"/>
                          </StackPanel>
                        </Border>
                      </StackPanel>
                    </DockPanel>
                    <DockPanel Margin="0,16,0,0">
                      <Border x:Name="NextIcon" DockPanel.Dock="Left" Width="38" Height="38" CornerRadius="19" Background="#1FF59E0B" VerticalAlignment="Top">
                        <TextBlock x:Name="NextGlyph" Text="&#xE7BA;" FontFamily="{StaticResource IconFont}" FontSize="15" Foreground="#FBBF24" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                      </Border>
                      <Button x:Name="BtnNextGo" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" Content="How?" VerticalAlignment="Top" Margin="12,0,0,0"/>
                      <StackPanel Margin="14,0,0,0">
                        <TextBlock x:Name="NextTitle" Text="Scanning..." FontSize="14.5" FontWeight="SemiBold" TextWrapping="Wrap"/>
                        <TextBlock x:Name="NextText" Text="" Style="{StaticResource Sub}" MaxHeight="58" TextTrimming="CharacterEllipsis"/>
                      </StackPanel>
                    </DockPanel>
                  </StackPanel>
                </Border>
                <Border Grid.Column="2" Style="{StaticResource Card}" Padding="20,18">
                  <StackPanel>
                    <TextBlock Text="Quick actions" Style="{StaticResource SectionTitle}"/>
                    <UniformGrid Columns="2" Margin="0,12,0,0">
                      <Button x:Name="ScScan" Style="{StaticResource GhostBtn}" Margin="0,0,6,6" Padding="10,9" FontSize="12.5" Content="PC Scan"/>
                      <Button x:Name="ScRestore" Style="{StaticResource GhostBtn}" Margin="0,0,0,6" Padding="10,9" FontSize="12.5" Content="Restore point"/>
                      <Button x:Name="ScClean" Style="{StaticResource GhostBtn}" Margin="0,0,6,0" Padding="10,9" FontSize="12.5" Content="Clean temp"/>
                      <Button x:Name="ScDns" Style="{StaticResource GhostBtn}" Padding="10,9" FontSize="12.5" Content="Flush DNS"/>
                    </UniformGrid>
                  </StackPanel>
                </Border>
              </Grid>
            </StackPanel>
          </ScrollViewer>

          <!-- QUICK BOOST -->
          <ScrollViewer x:Name="PageQuick" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel Margin="36,10,36,28" MaxWidth="1120">
              <TextBlock Text="Quick Boost" Style="{StaticResource H1}"/>
              <TextBlock Text="Pick how far you want to go. Only optimizations that suit this PC are applied - and every one can be undone." Style="{StaticResource Sub}"/>
              <UniformGrid Columns="3" Margin="0,22,-14,0">
                <RadioButton x:Name="QbSafe" Style="{StaticResource PresetCard}" Margin="0,0,14,0">
                  <StackPanel>
                    <TextBlock Text="Safe" FontSize="17" FontWeight="SemiBold"/>
                    <TextBlock Text="Zero-risk optimizations for every PC. Smoother and cleaner, nothing to think about." Foreground="#9AA5BF" FontSize="12.5" TextWrapping="Wrap" Margin="0,6,0,0"/>
                    <TextBlock x:Name="QbSafeCount" Text="" FontSize="12" Foreground="#5BE39A" Margin="0,12,0,0"/>
                  </StackPanel>
                </RadioButton>
                <RadioButton x:Name="QbComp" Style="{StaticResource PresetCard}" Margin="0,0,14,0" IsChecked="True">
                  <StackPanel>
                    <StackPanel Orientation="Horizontal">
                      <TextBlock Text="Competitive" FontSize="17" FontWeight="SemiBold"/>
                      <Border CornerRadius="6" Padding="7,1" Margin="8,0,0,0" Background="#26FF8A1F" VerticalAlignment="Center"><TextBlock Text="Recommended" FontSize="10.5" Foreground="#FFA24A"/></Border>
                    </StackPanel>
                    <TextBlock Text="Lowest input lag and ping for online games: power, timers, network and input tuned for competitive play." Foreground="#9AA5BF" FontSize="12.5" TextWrapping="Wrap" Margin="0,6,0,0"/>
                    <TextBlock x:Name="QbCompCount" Text="" FontSize="12" Foreground="#5BE39A" Margin="0,12,0,0"/>
                  </StackPanel>
                </RadioButton>
                <RadioButton x:Name="QbMax" Style="{StaticResource PresetCard}" Margin="0,0,14,0">
                  <StackPanel>
                    <TextBlock Text="Maximum" FontSize="17" FontWeight="SemiBold"/>
                    <TextBlock Text="Everything that improves performance, including small trade-offs. Advanced tweaks always stay manual." Foreground="#9AA5BF" FontSize="12.5" TextWrapping="Wrap" Margin="0,6,0,0"/>
                    <TextBlock x:Name="QbMaxCount" Text="" FontSize="12" Foreground="#5BE39A" Margin="0,12,0,0"/>
                  </StackPanel>
                </RadioButton>
              </UniformGrid>
              <StackPanel Orientation="Horizontal" Margin="0,22,0,0">
                <Button x:Name="BtnQbApply" Style="{StaticResource PrimaryBtn}" Padding="22,11" Content="Apply"/>
                <Button x:Name="BtnQbShow" Style="{StaticResource GhostBtn}" Content="Show what will change" Margin="10,0,0,0"/>
              </StackPanel>
              <TextBlock x:Name="QbDone" Text="" Visibility="Collapsed" Foreground="#5BE39A" FontSize="13" Margin="2,14,0,0"/>
              <Border x:Name="QbListBox" Style="{StaticResource Card}" Margin="0,14,0,0" Visibility="Collapsed">
                <StackPanel x:Name="QbList"/>
              </Border>
              <Border Style="{StaticResource Card}" Margin="0,28,0,0">
                <StackPanel>
                  <DockPanel>
                    <Button x:Name="BtnManage" DockPanel.Dock="Right" Style="{StaticResource SmallBtn}" Content="All optimizations"/>
                    <TextBlock Text="Most effective single optimizations" Style="{StaticResource SectionTitle}"/>
                  </DockPanel>
                  <StackPanel x:Name="FeatList" Margin="0,8,0,0"/>
                </StackPanel>
              </Border>
            </StackPanel>
          </ScrollViewer>

          <!-- MACROS -->
          <Grid x:Name="PageMacros" Visibility="Collapsed">
            <!-- main view -->
            <ScrollViewer x:Name="MacroMainView" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
              <StackPanel Margin="28,6,24,24">
                <DockPanel>
                  <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                    <Button x:Name="BtnOpenRecorder" Style="{StaticResource GhostBtn}" Content="Macro recorder" Margin="0,0,14,0"/>
                    <TextBlock Text="Macros on" Foreground="#9AA5BF" VerticalAlignment="Center" Margin="0,0,10,0"/>
                    <CheckBox x:Name="MacroEnabledTg" Style="{StaticResource Toggle}" VerticalAlignment="Center"/>
                  </StackPanel>
                  <StackPanel>
                    <TextBlock Text="Macros" Style="{StaticResource H1}"/>
                    <TextBlock x:Name="MacroSub" Text="Give your mouse buttons and hotkeys new jobs - per app, switching automatically. Works while Silvan Boost is open (minimized is fine)." Style="{StaticResource Sub}"/>
                  </StackPanel>
                </DockPanel>
                <Grid Margin="0,18,0,0">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="250"/>
                    <ColumnDefinition Width="14"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="14"/>
                    <ColumnDefinition Width="340"/>
                  </Grid.ColumnDefinitions>
                  <!-- profiles -->
                  <Border Style="{StaticResource Card}" Padding="14" VerticalAlignment="Top">
                    <StackPanel>
                      <TextBlock Text="PROFILES" Style="{StaticResource Label}" Margin="4,0,0,10"/>
                      <StackPanel x:Name="ProfileList"/>
                      <StackPanel Orientation="Horizontal" Margin="0,8,0,0">
                        <Button x:Name="BtnAddProfile" Style="{StaticResource GhostBtn}" Content="+ Add profile" Padding="12,7" FontSize="12.5"/>
                        <Button x:Name="BtnDelProfile" Style="{StaticResource GhostBtn}" Content="Remove" Padding="12,7" FontSize="12.5" Margin="6,0,0,0"/>
                      </StackPanel>
                      <DockPanel Margin="4,16,0,0">
                        <CheckBox x:Name="MacroAutoTg" DockPanel.Dock="Right" Style="{StaticResource Toggle}" VerticalAlignment="Center"/>
                        <TextBlock Text="Switch profiles automatically" FontSize="12.5" TextWrapping="Wrap" VerticalAlignment="Center" Margin="0,0,10,0"/>
                      </DockPanel>
                      <TextBlock x:Name="MacroActiveTxt" Text="" FontSize="11.5" Foreground="#5BE39A" Margin="4,8,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                  </Border>
                  <!-- devices + map + hotkeys -->
                  <StackPanel Grid.Column="2">
                    <UniformGrid Columns="2" Margin="0,0,-12,0">
                      <Border Style="{StaticResource Card}" Padding="14" Margin="0,0,12,12">
                        <DockPanel>
                          <Border x:Name="DevMouseArt" DockPanel.Dock="Left" Width="76" Height="56" CornerRadius="10" Background="#0E1628" ClipToBounds="True"/>
                          <StackPanel Margin="12,0,0,0" VerticalAlignment="Center">
                            <TextBlock Text="MOUSE" Style="{StaticResource Label}"/>
                            <TextBlock x:Name="DevMouseName" Text="Detecting..." FontSize="13.5" FontWeight="SemiBold" TextTrimming="CharacterEllipsis" Margin="0,2,0,0"/>
                            <DockPanel Margin="0,2,0,0">
                              <Button x:Name="BtnDevMousePhoto" DockPanel.Dock="Right" Style="{StaticResource SmallBtn}" Content="Photo" Padding="8,2"/>
                              <TextBlock x:Name="DevMouseSub" Text="" FontSize="11.5" Foreground="#7F8BA6" TextTrimming="CharacterEllipsis" VerticalAlignment="Center"/>
                            </DockPanel>
                          </StackPanel>
                        </DockPanel>
                      </Border>
                      <Border Style="{StaticResource Card}" Padding="14" Margin="0,0,12,12">
                        <DockPanel>
                          <Border x:Name="DevKbdArt" DockPanel.Dock="Left" Width="76" Height="56" CornerRadius="10" Background="#0E1628" ClipToBounds="True"/>
                          <StackPanel Margin="12,0,0,0" VerticalAlignment="Center">
                            <TextBlock Text="KEYBOARD" Style="{StaticResource Label}"/>
                            <TextBlock x:Name="DevKbdName" Text="Detecting..." FontSize="13.5" FontWeight="SemiBold" TextTrimming="CharacterEllipsis" Margin="0,2,0,0"/>
                            <DockPanel Margin="0,2,0,0">
                              <Button x:Name="BtnDevKbdPhoto" DockPanel.Dock="Right" Style="{StaticResource SmallBtn}" Content="Photo" Padding="8,2"/>
                              <TextBlock x:Name="DevKbdSub" Text="" FontSize="11.5" Foreground="#7F8BA6" TextTrimming="CharacterEllipsis" VerticalAlignment="Center"/>
                            </DockPanel>
                          </StackPanel>
                        </DockPanel>
                      </Border>
                    </UniformGrid>
                    <Border Style="{StaticResource Card}" Padding="18">
                      <StackPanel>
                        <DockPanel>
                          <TextBlock x:Name="MapProfileTxt" DockPanel.Dock="Right" Text="" FontSize="12" Foreground="#7F8BA6" VerticalAlignment="Center"/>
                          <TextBlock Text="Mouse buttons" Style="{StaticResource SectionTitle}"/>
                        </DockPanel>
                        <Grid Margin="0,14,0,0">
                          <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="22"/>
                            <ColumnDefinition Width="*"/>
                          </Grid.ColumnDefinitions>
                          <Canvas Width="150" Height="226">
                            <Border Canvas.Left="12" Canvas.Top="4" Width="128" Height="216" CornerRadius="64,64,56,56" Background="#16213A" BorderBrush="#2A3858" BorderThickness="2"/>
                            <Rectangle Canvas.Left="75" Canvas.Top="6" Width="2" Height="82" Fill="#2A3858"/>
                            <Rectangle Canvas.Left="14" Canvas.Top="88" Width="124" Height="2" Fill="#2A3858"/>
                            <TextBlock Canvas.Left="38" Canvas.Top="44" Text="L" FontSize="12" Foreground="#4A5675"/>
                            <TextBlock Canvas.Left="106" Canvas.Top="44" Text="R" FontSize="12" Foreground="#4A5675"/>
                            <Button x:Name="HsMid" Style="{StaticResource HotSpot}" Tag="6" Canvas.Left="69" Canvas.Top="26" Width="14" Height="34" ToolTip="Middle button"/>
                            <Border Canvas.Left="71" Canvas.Top="68" Width="10" Height="14" CornerRadius="3" Background="#1A2540" ToolTip="DPI button - set in your mouse's own software"/>
                            <Button x:Name="HsFwd" Style="{StaticResource HotSpot}" Tag="4" Canvas.Left="6" Canvas.Top="104" Width="12" Height="30" ToolTip="Forward (side)"/>
                            <Button x:Name="HsBack" Style="{StaticResource HotSpot}" Tag="4" Canvas.Left="6" Canvas.Top="140" Width="12" Height="30" ToolTip="Back (side)"/>
                          </Canvas>
                          <StackPanel Grid.Column="2" VerticalAlignment="Center">
                      <Button x:Name="MapMid" Style="{StaticResource GhostBtn}" HorizontalContentAlignment="Stretch" Padding="12,8" Margin="0,0,0,6">
                        <DockPanel>
                          <Border DockPanel.Dock="Right" CornerRadius="6" Padding="8,2" Background="#1A2540" Margin="8,0,0,0">
                            <TextBlock x:Name="MapMidTxt" Text="Default" FontSize="11.5" Foreground="#9AA5BF" MaxWidth="170" TextTrimming="CharacterEllipsis"/>
                          </Border>
                          <TextBlock Text="Middle button" FontSize="13" VerticalAlignment="Center"/>
                        </DockPanel>
                      </Button>
                      <Button x:Name="MapBack" Style="{StaticResource GhostBtn}" HorizontalContentAlignment="Stretch" Padding="12,8" Margin="0,0,0,6">
                        <DockPanel>
                          <Border DockPanel.Dock="Right" CornerRadius="6" Padding="8,2" Background="#1A2540" Margin="8,0,0,0">
                            <TextBlock x:Name="MapBackTxt" Text="Default" FontSize="11.5" Foreground="#9AA5BF" MaxWidth="170" TextTrimming="CharacterEllipsis"/>
                          </Border>
                          <TextBlock Text="Back (side)" FontSize="13" VerticalAlignment="Center"/>
                        </DockPanel>
                      </Button>
                      <Button x:Name="MapFwd" Style="{StaticResource GhostBtn}" HorizontalContentAlignment="Stretch" Padding="12,8" Margin="0,0,0,6">
                        <DockPanel>
                          <Border DockPanel.Dock="Right" CornerRadius="6" Padding="8,2" Background="#1A2540" Margin="8,0,0,0">
                            <TextBlock x:Name="MapFwdTxt" Text="Default" FontSize="11.5" Foreground="#9AA5BF" MaxWidth="170" TextTrimming="CharacterEllipsis"/>
                          </Border>
                          <TextBlock Text="Forward (side)" FontSize="13" VerticalAlignment="Center"/>
                        </DockPanel>
                      </Button>
                            <TextBlock Text="Left and right click stay as they are, so you can never lock yourself out. DPI and lighting are stored on the mouse - change them in your mouse's own software." FontSize="11.5" Foreground="#7F8BA6" TextWrapping="Wrap" Margin="2,6,0,0"/>
                          </StackPanel>
                        </Grid>
                      </StackPanel>
                    </Border>
                    <Border Style="{StaticResource Card}" Padding="18" Margin="0,12,0,0">
                      <StackPanel>
                        <DockPanel>
                          <Button x:Name="BtnAddHotkey" DockPanel.Dock="Right" Style="{StaticResource SmallBtn}" Content="+ Add hotkey"/>
                          <TextBlock Text="Keyboard hotkeys" Style="{StaticResource SectionTitle}"/>
                        </DockPanel>
                        <TextBlock x:Name="HotkeyHint" Text="" FontSize="12" Foreground="#FFA24A" Margin="0,6,0,0" Visibility="Collapsed"/>
                        <StackPanel x:Name="HotkeyList" Margin="0,10,0,0"/>
                      </StackPanel>
                    </Border>
                  </StackPanel>
                  <!-- editor -->
                  <Border Grid.Column="4" Style="{StaticResource Card}" Padding="18" VerticalAlignment="Top">
                    <StackPanel>
                      <TextBlock x:Name="EdTitle" Text="Middle button" FontSize="17" FontWeight="SemiBold"/>
                      <TextBlock x:Name="EdSub" Text="" FontSize="12" Foreground="#7F8BA6" Margin="0,2,0,12"/>
                      <Border x:Name="EdGameNote" CornerRadius="10" Background="#1AF59E0B" Padding="12,9" Margin="0,0,0,12" Visibility="Collapsed">
                        <TextBlock Text="Game profile: only 1:1 key remaps, Sniper mode and Disable are allowed. Anti-cheat can ban automated input like macros, text or key combos." FontSize="12" Foreground="#FBBF24" TextWrapping="Wrap"/>
                      </Border>
                    <RadioButton x:Name="OptRemap" Style="{StaticResource OptRow}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE765;" FontFamily="{StaticResource IconFont}" FontSize="14" Width="22" VerticalAlignment="Center" Foreground="#9AA5BF"/>
                        <TextBlock Text="Remap to a key" FontSize="13" VerticalAlignment="Center" Margin="6,0,0,0"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="OptCombo" Style="{StaticResource OptRow}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE8A5;" FontFamily="{StaticResource IconFont}" FontSize="14" Width="22" VerticalAlignment="Center" Foreground="#9AA5BF"/>
                        <TextBlock Text="Key combination" FontSize="13" VerticalAlignment="Center" Margin="6,0,0,0"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="OptText" Style="{StaticResource OptRow}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE8D2;" FontFamily="{StaticResource IconFont}" FontSize="14" Width="22" VerticalAlignment="Center" Foreground="#9AA5BF"/>
                        <TextBlock Text="Type text" FontSize="13" VerticalAlignment="Center" Margin="6,0,0,0"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="OptMacro" Style="{StaticResource OptRow}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE7C8;" FontFamily="{StaticResource IconFont}" FontSize="14" Width="22" VerticalAlignment="Center" Foreground="#9AA5BF"/>
                        <TextBlock Text="Run a macro" FontSize="13" VerticalAlignment="Center" Margin="6,0,0,0"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="OptRun" Style="{StaticResource OptRow}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE8A7;" FontFamily="{StaticResource IconFont}" FontSize="14" Width="22" VerticalAlignment="Center" Foreground="#9AA5BF"/>
                        <TextBlock Text="Open app or website" FontSize="13" VerticalAlignment="Center" Margin="6,0,0,0"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="OptMedia" Style="{StaticResource OptRow}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE768;" FontFamily="{StaticResource IconFont}" FontSize="14" Width="22" VerticalAlignment="Center" Foreground="#9AA5BF"/>
                        <TextBlock Text="Media and volume" FontSize="13" VerticalAlignment="Center" Margin="6,0,0,0"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="OptSniper" Style="{StaticResource OptRow}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE7B3;" FontFamily="{StaticResource IconFont}" FontSize="14" Width="22" VerticalAlignment="Center" Foreground="#9AA5BF"/>
                        <TextBlock Text="Sniper mode (hold = slower pointer)" FontSize="13" VerticalAlignment="Center" Margin="6,0,0,0"/>
                      </StackPanel>
                    </RadioButton>
                    <RadioButton x:Name="OptDisable" Style="{StaticResource OptRow}">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE711;" FontFamily="{StaticResource IconFont}" FontSize="14" Width="22" VerticalAlignment="Center" Foreground="#9AA5BF"/>
                        <TextBlock Text="Disable this button" FontSize="13" VerticalAlignment="Center" Margin="6,0,0,0"/>
                      </StackPanel>
                    </RadioButton>

                      <Border CornerRadius="10" Background="#0E1628" Padding="12" Margin="0,6,0,0">
                        <Grid>
                          <StackPanel x:Name="FRemap">
                            <TextBlock Text="Key to send" Style="{StaticResource Label}"/>
                            <Button x:Name="EdRemapKey" Style="{StaticResource GhostBtn}" Content="Click, then press a key" Margin="0,8,0,0"/>
                          </StackPanel>
                          <StackPanel x:Name="FCombo" Visibility="Collapsed">
                            <TextBlock Text="Key combination" Style="{StaticResource Label}"/>
                            <Button x:Name="EdComboKey" Style="{StaticResource GhostBtn}" Content="Click, then press e.g. Ctrl + C" Margin="0,8,0,0"/>
                          </StackPanel>
                          <StackPanel x:Name="FText" Visibility="Collapsed">
                            <TextBlock Text="Text to type" Style="{StaticResource Label}"/>
                            <TextBox x:Name="EdText" Style="{StaticResource Field}" Height="72" AcceptsReturn="True" TextWrapping="Wrap" Margin="0,8,0,0"/>
                          </StackPanel>
                          <StackPanel x:Name="FMacro" Visibility="Collapsed">
                            <TextBlock Text="Macro" Style="{StaticResource Label}"/>
                            <WrapPanel x:Name="EdMacroChips" Margin="0,8,0,0"/>
                            <Button x:Name="BtnEdMacros" Style="{StaticResource SmallBtn}" Content="Open macro recorder" HorizontalAlignment="Left" Margin="0,4,0,0"/>
                          </StackPanel>
                          <StackPanel x:Name="FRun" Visibility="Collapsed">
                            <TextBlock Text="Program, file or website" Style="{StaticResource Label}"/>
                            <TextBox x:Name="EdRunPath" Style="{StaticResource Field}" Margin="0,8,0,0"/>
                            <Button x:Name="BtnEdBrowse" Style="{StaticResource SmallBtn}" Content="Browse..." HorizontalAlignment="Left" Margin="0,8,0,0"/>
                          </StackPanel>
                          <StackPanel x:Name="FMedia" Visibility="Collapsed">
                            <TextBlock Text="Media action" Style="{StaticResource Label}"/>
                            <WrapPanel Margin="0,8,0,0">
                              <RadioButton x:Name="MdPlay" Content="Play / Pause" GroupName="media" Tag="playpause" Style="{StaticResource Chip}" Margin="0,0,6,6"/><RadioButton x:Name="MdNext" Content="Next" GroupName="media" Tag="next" Style="{StaticResource Chip}" Margin="0,0,6,6"/><RadioButton x:Name="MdPrev" Content="Previous" GroupName="media" Tag="prev" Style="{StaticResource Chip}" Margin="0,0,6,6"/><RadioButton x:Name="MdUp" Content="Volume +" GroupName="media" Tag="volup" Style="{StaticResource Chip}" Margin="0,0,6,6"/><RadioButton x:Name="MdDown" Content="Volume -" GroupName="media" Tag="voldown" Style="{StaticResource Chip}" Margin="0,0,6,6"/><RadioButton x:Name="MdMute" Content="Mute" GroupName="media" Tag="mute" Style="{StaticResource Chip}" Margin="0,0,6,6"/>
                            </WrapPanel>
                          </StackPanel>
                          <StackPanel x:Name="FSniper" Visibility="Collapsed">
                            <TextBlock Text="Pointer speed while held" Style="{StaticResource Label}"/>
                            <StackPanel Orientation="Horizontal" Margin="0,8,0,0">
                              <Button x:Name="BtnSnMinus" Style="{StaticResource GhostBtn}" Content="-" Padding="14,6"/>
                              <TextBlock x:Name="EdSnVal" Text="4" FontSize="20" FontWeight="SemiBold" Width="56" TextAlignment="Center" VerticalAlignment="Center"/>
                              <Button x:Name="BtnSnPlus" Style="{StaticResource GhostBtn}" Content="+" Padding="14,6"/>
                            </StackPanel>
                            <TextBlock Text="Windows scale 1 - 20 (normal is 10). Your normal speed comes back when you let go." FontSize="11.5" Foreground="#7F8BA6" TextWrapping="Wrap" Margin="0,8,0,0"/>
                          </StackPanel>
                          <StackPanel x:Name="FDisable" Visibility="Collapsed">
                            <TextBlock Text="The button does nothing while this profile is active." FontSize="12.5" Foreground="#9AA5BF" TextWrapping="Wrap"/>
                          </StackPanel>
                        </Grid>
                      </Border>
                      <StackPanel Orientation="Horizontal" Margin="0,14,0,0">
                        <Button x:Name="BtnEdSave" Style="{StaticResource PrimaryBtn}" Content="Save"/>
                        <Button x:Name="BtnEdClear" Style="{StaticResource GhostBtn}" Content="Reset to default" Margin="8,0,0,0"/>
                      </StackPanel>
                      <TextBlock x:Name="EdMsg" Text="" FontSize="12" Foreground="#5BE39A" Margin="2,10,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                  </Border>
                </Grid>
              </StackPanel>
            </ScrollViewer>

            <!-- recorder view -->
            <ScrollViewer x:Name="MacroRecView" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
              <StackPanel Margin="28,6,24,24">
                <Button x:Name="BtnRecBack" Style="{StaticResource SmallBtn}" Content="Back to Macros" HorizontalAlignment="Left"/>
                <TextBlock Text="Macro recorder" Style="{StaticResource H1}" Margin="0,10,0,0"/>
                <TextBlock Text="Record keys and clicks once, then put the macro on any button or hotkey. Changes save automatically." Style="{StaticResource Sub}"/>
                <Grid Margin="0,18,0,0">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="250"/>
                    <ColumnDefinition Width="14"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>
                  <Border Style="{StaticResource Card}" Padding="14" VerticalAlignment="Top">
                    <StackPanel>
                      <TextBlock Text="SAVED MACROS" Style="{StaticResource Label}" Margin="4,0,0,10"/>
                      <StackPanel x:Name="MacList"/>
                      <Button x:Name="BtnMacNew" Style="{StaticResource GhostBtn}" Content="+ New macro" HorizontalAlignment="Left" Padding="12,7" FontSize="12.5" Margin="0,8,0,0"/>
                    </StackPanel>
                  </Border>
                  <Border Grid.Column="2" Style="{StaticResource Card}" Padding="20">
                    <StackPanel x:Name="MacEditor">
                      <DockPanel>
                        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                          <Button x:Name="BtnMacDel" Style="{StaticResource GhostBtn}" Content="Delete" Padding="12,7" Margin="0,0,8,0"/>
                          <Button x:Name="BtnMacTest" Style="{StaticResource GhostBtn}" Content="Test" Padding="12,7" Margin="0,0,8,0"/>
                          <Button x:Name="BtnRec" Style="{StaticResource PrimaryBtn}" Content="Record"/>
                        </StackPanel>
                        <TextBox x:Name="MacName" Style="{StaticResource Field}" FontSize="15" Margin="0,0,16,0"/>
                      </DockPanel>
                      <Border x:Name="MacRecBanner" CornerRadius="10" Background="#26EF4444" Padding="12,9" Margin="0,14,0,0" Visibility="Collapsed">
                        <StackPanel Orientation="Horizontal">
                          <Ellipse x:Name="MacRecDot" Width="9" Height="9" Fill="#F87171" VerticalAlignment="Center" Margin="0,0,10,0"/>
                          <TextBlock x:Name="MacRecTxt" Text="" FontSize="12.5" Foreground="#FCA5A5" TextWrapping="Wrap"/>
                        </StackPanel>
                      </Border>
                      <WrapPanel Margin="0,16,0,0">
                        <TextBlock Text="Repeat:" Foreground="#9AA5BF" VerticalAlignment="Center" Margin="0,0,10,6"/>
                        <RadioButton x:Name="RepOnce" Content="Once" GroupName="rep" Tag="once" Style="{StaticResource Chip}" Margin="0,0,6,6"/><RadioButton x:Name="RepHeld" Content="While held" GroupName="rep" Tag="held" Style="{StaticResource Chip}" Margin="0,0,6,6"/><RadioButton x:Name="RepToggle" Content="Toggle on / off" GroupName="rep" Tag="toggle" Style="{StaticResource Chip}" Margin="0,0,6,6"/>
                        <TextBlock Text="Record real delays" Foreground="#9AA5BF" VerticalAlignment="Center" Margin="18,0,10,6"/>
                        <CheckBox x:Name="RecDelaysTg" Style="{StaticResource Toggle}" IsChecked="True" VerticalAlignment="Center" Margin="0,0,0,6"/>
                      </WrapPanel>
                      <TextBlock x:Name="MacInfo" Text="" FontSize="12" Foreground="#7F8BA6" Margin="0,6,0,0"/>
                      <StackPanel x:Name="MacSteps" Margin="0,12,0,0"/>
                      <WrapPanel Margin="0,10,0,0">
                        <TextBlock Text="Insert:" Foreground="#9AA5BF" VerticalAlignment="Center" Margin="0,0,10,6"/>
                        <Button x:Name="BtnInsKey" Style="{StaticResource SmallBtn}" Content="+ Key" Margin="0,0,6,6"/>
                        <Button x:Name="BtnInsDelay" Style="{StaticResource SmallBtn}" Content="+ Delay" Margin="0,0,6,6"/>
                        <Button x:Name="BtnInsClick" Style="{StaticResource SmallBtn}" Content="+ Left click" Margin="0,0,6,6"/>
                        <Button x:Name="BtnInsText" Style="{StaticResource SmallBtn}" Content="+ Text" Margin="0,0,6,6"/>
                      </WrapPanel>
                      <TextBlock x:Name="MacMsg" Text="" FontSize="12" Foreground="#5BE39A" Margin="2,8,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                  </Border>
                </Grid>
              </StackPanel>
            </ScrollViewer>
          </Grid>

          <!-- SCANNER -->
          <ScrollViewer x:Name="PageScan" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel Margin="28,6,28,24">
              <DockPanel>
                <Button x:Name="BtnRescan" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" VerticalAlignment="Center">
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="&#xE72C;" FontFamily="{StaticResource IconFont}" FontSize="13" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBlock Text="Rescan"/>
                  </StackPanel>
                </Button>
                <StackPanel>
                  <TextBlock Text="PC Scanner" Style="{StaticResource H1}"/>
                  <TextBlock Text="Your detected hardware and a gaming health check." Style="{StaticResource Sub}"/>
                </StackPanel>
              </DockPanel>
              <UniformGrid x:Name="HwGrid" Columns="3" Margin="0,20,0,0"/>
              <TextBlock Text="Gaming health check" Style="{StaticResource SectionTitle}" Margin="0,14,0,12"/>
              <StackPanel x:Name="RecList"/>
            </StackPanel>
          </ScrollViewer>

          <!-- OPTIMIZATIONS -->
          <Grid x:Name="PageTweaks" Visibility="Collapsed" Margin="28,6,16,0">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="*"/>
            </Grid.RowDefinitions>
            <DockPanel Margin="0,0,12,0">
              <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                <Button x:Name="BtnRevertAll" Style="{StaticResource GhostBtn}" Content="Revert all" Margin="0,0,8,0"/>
                <Button x:Name="BtnPresetSafe" Style="{StaticResource GhostBtn}" Content="Apply recommended" Margin="0,0,8,0"/>
                <Button x:Name="BtnPresetMax" Style="{StaticResource PrimaryBtn}">
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="&#xE945;" FontFamily="{StaticResource IconFont}" FontSize="13" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBlock Text="Max performance"/>
                  </StackPanel>
                </Button>
              </StackPanel>
              <StackPanel>
                <TextBlock Text="Optimizations" Style="{StaticResource H1}"/>
                <TextBlock x:Name="TweakSub" Text="" Style="{StaticResource Sub}"/>
              </StackPanel>
            </DockPanel>
            <DockPanel Grid.Row="1" Margin="0,18,12,4">
              <TextBox x:Name="SearchBox" Tag="Search optimizations..." DockPanel.Dock="Right" Width="250" Height="36" Style="{StaticResource Search}" VerticalAlignment="Top" Margin="12,0,0,0"/>
              <WrapPanel x:Name="ChipBar"/>
            </DockPanel>
            <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
              <StackPanel Margin="0,4,4,20">
                <TextBlock x:Name="ShowCount" Foreground="#9AA5BF" FontSize="12" Margin="2,0,0,10"/>
                <UniformGrid x:Name="TweakGrid" Columns="3" VerticalAlignment="Top"/>
              </StackPanel>
            </ScrollViewer>
          </Grid>

          <!-- GAMES -->
          <Grid x:Name="PageGames" Visibility="Collapsed" Margin="28,6,16,0">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="*"/>
            </Grid.RowDefinitions>
            <DockPanel Margin="0,0,12,16">
              <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                <Button x:Name="BtnGamesRescan" Style="{StaticResource GhostBtn}" Margin="0,0,8,0">
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="&#xE72C;" FontFamily="{StaticResource IconFont}" FontSize="13" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBlock Text="Search again"/>
                  </StackPanel>
                </Button>
                <Button x:Name="BtnAddGame" Style="{StaticResource PrimaryBtn}">
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="&#xE710;" FontFamily="{StaticResource IconFont}" FontSize="13" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBlock Text="Add your own game"/>
                  </StackPanel>
                </Button>
              </StackPanel>
              <StackPanel>
                <TextBlock Text="Game Presets" Style="{StaticResource H1}"/>
                <TextBlock x:Name="GamesSub" Text="" Style="{StaticResource Sub}"/>
              </StackPanel>
            </DockPanel>
            <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
              <UniformGrid x:Name="GameGrid" Columns="3" VerticalAlignment="Top" Margin="0,0,4,20"/>
            </ScrollViewer>
          </Grid>

          <!-- PRO SETTINGS -->
          <Grid x:Name="PagePro" Visibility="Collapsed" Margin="28,6,16,0">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="*"/>
            </Grid.RowDefinitions>
            <StackPanel Margin="0,0,12,0">
              <TextBlock Text="Pro Settings" Style="{StaticResource H1}"/>
              <TextBlock Text="The in-game settings top players use for maximum FPS and visibility - pick a game." Style="{StaticResource Sub}"/>
            </StackPanel>
            <WrapPanel x:Name="ProChips" Grid.Row="1" Margin="0,16,12,4"/>
            <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
              <StackPanel Margin="0,6,12,20">
                <Border Style="{StaticResource Card}">
                  <StackPanel>
                    <DockPanel>
                      <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                        <Button x:Name="BtnProOpen" Style="{StaticResource GhostBtn}" Content="Current pro configs" Margin="0,0,8,0" Padding="12,7"/>
                        <Button x:Name="BtnProOptimize" Style="{StaticResource PrimaryBtn}" Content="Optimize Windows for this game" Padding="14,7"/>
                      </StackPanel>
                      <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                        <TextBlock x:Name="ProTitle" Text="" FontSize="21" FontWeight="SemiBold" VerticalAlignment="Center"/>
                        <Border x:Name="ProKindBadge" CornerRadius="6" Padding="8,2" Margin="12,0,0,0" VerticalAlignment="Center" Background="#26FF8A1F">
                          <TextBlock x:Name="ProKind" Text="" FontSize="11" FontWeight="SemiBold" Foreground="#FFB06A"/>
                        </Border>
                      </StackPanel>
                    </DockPanel>
                    <TextBlock x:Name="ProNote" Text="" Style="{StaticResource Sub}" Margin="0,8,0,0"/>
                    <Border x:Name="ProCfgBar" CornerRadius="10" Background="#142ED47A" BorderBrush="#332ED47A" BorderThickness="1" Padding="14,10" Margin="0,12,0,0" Visibility="Collapsed">
                      <DockPanel>
                        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                          <Button x:Name="BtnProCfgUndo" Style="{StaticResource GhostBtn}" Content="Undo" Padding="12,6" Margin="0,0,8,0" Visibility="Collapsed"/>
                          <Button x:Name="BtnProCfgApply" Style="{StaticResource PrimaryBtn}" Content="Apply to game" Padding="14,6"/>
                        </StackPanel>
                        <StackPanel VerticalAlignment="Center">
                          <TextBlock Text="Write these settings straight into the game" FontWeight="SemiBold" FontSize="13"/>
                          <TextBlock x:Name="ProCfgTxt" Text="Your current game config is backed up first. Close the game before applying." FontSize="12" Foreground="#9AA5BF" TextWrapping="Wrap" Margin="0,2,0,0"/>
                        </StackPanel>
                      </DockPanel>
                    </Border>
                    <StackPanel x:Name="ProTable" Margin="0,18,0,0"/>
                  </StackPanel>
                </Border>
                <TextBlock Text="Compiled from public pro-settings guides (2025-2026). Every pro is a little different - use these as a strong starting point and adjust to taste." Foreground="#7F8BA6" FontSize="12" Margin="2,12,0,0" TextWrapping="Wrap"/>
              </StackPanel>
            </ScrollViewer>
          </Grid>

          <!-- LIVE MONITOR -->
          <ScrollViewer x:Name="PageLive" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel Margin="28,6,28,24">
              <DockPanel>
                <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                  <TextBlock Text="Auto-detect games" Foreground="#A9B3CC" VerticalAlignment="Center" Margin="0,0,10,0"/>
                  <CheckBox x:Name="LiveAuto" Style="{StaticResource Toggle}" IsChecked="True" VerticalAlignment="Center"/>
                </StackPanel>
                <StackPanel>
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="Live Monitor" Style="{StaticResource H1}"/>
                    <Border x:Name="LiveStateBadge" CornerRadius="6" Padding="8,2" Margin="12,0,0,0" VerticalAlignment="Center" Background="#1A2440">
                      <TextBlock x:Name="LiveState" Text="IDLE" FontSize="11" FontWeight="Bold" Foreground="#A9B3CC"/>
                    </Border>
                  </StackPanel>
                  <TextBlock x:Name="LiveTitle" Text="Waiting for a game... Start any game from Game Presets and it is detected automatically." Style="{StaticResource Sub}"/>
                </StackPanel>
              </DockPanel>
              <Border Style="{StaticResource Card}" Margin="0,16,0,0" Padding="18,14">
                <DockPanel>
                  <CheckBox x:Name="AutoGameTg" DockPanel.Dock="Right" Style="{StaticResource Toggle}" VerticalAlignment="Center" Margin="14,0,0,0"/>
                  <Border DockPanel.Dock="Left" Width="38" Height="38" CornerRadius="11" Background="#1AFF8A1F" VerticalAlignment="Center">
                    <TextBlock Text="&#xE7FC;" FontFamily="{StaticResource IconFont}" FontSize="16" Foreground="#FF8A1F" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                  </Border>
                  <StackPanel Margin="14,0,0,0" VerticalAlignment="Center">
                    <TextBlock Text="Auto game mode" FontSize="14" FontWeight="SemiBold"/>
                    <TextBlock Text="When a game starts, the game gets high priority, browsers and launchers in the background get low priority and downloads pause. Everything goes back when you close the game." FontSize="12" Foreground="#9AA5BF" TextWrapping="Wrap" Margin="0,2,0,0"/>
                  </StackPanel>
                </DockPanel>
              </Border>
              <UniformGrid Columns="4" Margin="0,18,0,0">
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="FPS" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="LvFps" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="LvFpsSub" Text="frames per second" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="1% LOW" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="LvLow" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="LvLowSub" Text="slowest 1% of frames" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="FRAMETIME" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="LvFt" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="LvFtSub" Text="time per frame" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="STUTTERS" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="LvStut" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="LvStutSub" Text="big frame spikes" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="GPU" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="LvGpu" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="LvGpuSub" Text="" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="CPU" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="LvCpu" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="LvCpuSub" Text="" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="MEMORY" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="LvMem" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="LvMemSub" Text="" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="PING (1.1.1.1)" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="LvPing" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="LvPingSub" Text="" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
              </UniformGrid>
              <Border Style="{StaticResource Card}" Margin="0,0,10,14">
                <StackPanel>
                  <DockPanel>
                    <TextBlock x:Name="LiveGraphMax" DockPanel.Dock="Right" Text="" FontSize="11" Foreground="#7F8BA6"/>
                    <TextBlock Text="FRAMETIME GRAPH  -  flat and low = smooth, spikes = stutter" Style="{StaticResource Label}"/>
                  </DockPanel>
                  <Canvas x:Name="LiveGraph" Height="110" Margin="0,10,0,0" ClipToBounds="True">
                    <Polyline x:Name="LiveLine" Stroke="#FF8A1F" StrokeThickness="2" StrokeLineJoin="Round"/>
                  </Canvas>
                </StackPanel>
              </Border>
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="1.6*"/>
                  <ColumnDefinition Width="14"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <StackPanel>
                  <TextBlock Text="Problems detected" Style="{StaticResource SectionTitle}" Margin="2,0,0,10"/>
                  <TextBlock x:Name="LiveEmpty" Text="No problems so far. Problems appear here live while you play - with the cause and how to fix it." Foreground="#9AA5BF" TextWrapping="Wrap" Margin="2,0,0,10"/>
                  <StackPanel x:Name="LiveProbList"/>
                </StackPanel>
                <StackPanel Grid.Column="2" Margin="0,0,10,0">
                  <Border x:Name="LiveLastCard" Style="{StaticResource Card}" Margin="0,0,0,12" Visibility="Collapsed">
                    <StackPanel>
                      <TextBlock Text="LAST SESSION REPORT" Style="{StaticResource Label}"/>
                      <TextBlock x:Name="LiveLastText" Text="" TextWrapping="Wrap" FontSize="12.5" Margin="0,8,0,0" LineHeight="19"/>
                    </StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Margin="0,0,0,12">
                    <StackPanel>
                      <TextBlock Text="BACKGROUND LOAD" Style="{StaticResource Label}"/>
                      <TextBlock x:Name="LiveBg" Text="Shown while a game is running." TextWrapping="Wrap" FontSize="12.5" Margin="0,8,0,0" Foreground="#A9B3CC"/>
                    </StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}">
                    <StackPanel>
                      <TextBlock Text="HOW IT WORKS" Style="{StaticResource Label}"/>
                      <TextBlock TextWrapping="Wrap" FontSize="12.5" Margin="0,8,0,0" Foreground="#A9B3CC" Text="Keep Silvan Boost open (minimized is fine) and start a game. It is detected automatically and measured live: FPS and frame times (via Intel PresentMon), CPU, GPU, temperatures, memory, drive and ping. When the game closes, Silvan Boost pops up with a session report. Nothing is injected into the game, so it is safe with anti-cheat."/>
                    </StackPanel>
                  </Border>
                </StackPanel>
              </Grid>
              <Border Style="{StaticResource Card}" Margin="0,14,0,0">
                <StackPanel>
                  <DockPanel>
                    <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                      <Ellipse Width="8" Height="8" Fill="#FF8A1F" VerticalAlignment="Center"/>
                      <TextBlock Text="Average FPS" FontSize="11.5" Foreground="#9AA5BF" Margin="6,0,14,0" VerticalAlignment="Center"/>
                      <Ellipse Width="8" Height="8" Fill="#2ED47A" VerticalAlignment="Center"/>
                      <TextBlock Text="1% low" FontSize="11.5" Foreground="#9AA5BF" Margin="6,0,0,0" VerticalAlignment="Center"/>
                    </StackPanel>
                    <TextBlock Text="FPS history" Style="{StaticResource SectionTitle}"/>
                  </DockPanel>
                  <WrapPanel x:Name="HistChips" Margin="0,12,0,0"/>
                  <TextBlock x:Name="HistInfo" Text="Play a game for at least one minute and your sessions show up here - so you can see if a game or driver update cost you FPS." FontSize="12.5" Foreground="#9AA5BF" TextWrapping="Wrap" Margin="0,4,0,0"/>
                  <Grid Height="170" Margin="0,12,0,0">
                    <Canvas x:Name="HistCanvas" ClipToBounds="True" Background="Transparent"/>
                  </Grid>
                </StackPanel>
              </Border>
            </StackPanel>
          </ScrollViewer>

          <!-- BENCHMARK -->
          <ScrollViewer x:Name="PageBench" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel Margin="28,6,28,24" MaxWidth="1080" HorizontalAlignment="Left">
              <TextBlock Text="Before / after benchmark" Style="{StaticResource H1}"/>
              <TextBlock Text="See what the boost really does: measure a game before and after, then share the result." Style="{StaticResource Sub}"/>
              <UniformGrid Columns="3" Margin="0,20,0,0">
                <Border x:Name="BenchStep1" Style="{StaticResource Card}" Margin="0,0,6,0" Padding="20,18">
                  <DockPanel>
                    <StackPanel DockPanel.Dock="Bottom" Margin="0,14,0,0">
                      <Button x:Name="BtnBench1" Style="{StaticResource PrimaryBtn}" Content="Start measuring" HorizontalAlignment="Left"/>
                      <TextBlock x:Name="BenchS1" Text="" FontSize="12" Foreground="#7F8BA6" Margin="0,10,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                    <StackPanel>
                      <Border x:Name="BenchNum1" Width="32" Height="32" CornerRadius="16" Background="#24FF8A1F" BorderBrush="#59FF8A1F" BorderThickness="1" HorizontalAlignment="Left">
                        <TextBlock x:Name="BenchNumTxt1" Text="1" FontWeight="Bold" FontSize="14" Foreground="#FFB36B" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                      </Border>
                      <TextBlock Text="Measure before" FontSize="16" FontWeight="SemiBold" Margin="0,12,0,0"/>
                      <TextBlock Text="Click Start, then play your game for 2 minutes like you normally do." FontSize="12.5" Foreground="#9AA5BF" TextWrapping="Wrap" Margin="0,4,0,0"/>
                    </StackPanel>
                  </DockPanel>
                </Border>
                <Border x:Name="BenchStep2" Style="{StaticResource Card}" Margin="6,0,6,0" Padding="20,18">
                  <DockPanel>
                    <StackPanel DockPanel.Dock="Bottom" Margin="0,14,0,0">
                      <Button x:Name="BtnBench2" Style="{StaticResource GhostBtn}" Content="Open Quick Boost" HorizontalAlignment="Left"/>
                      <TextBlock x:Name="BenchS2" Text="" FontSize="12" Foreground="#7F8BA6" Margin="0,10,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                    <StackPanel>
                      <Border x:Name="BenchNum2" Width="32" Height="32" CornerRadius="16" Background="#24FF8A1F" BorderBrush="#59FF8A1F" BorderThickness="1" HorizontalAlignment="Left">
                        <TextBlock x:Name="BenchNumTxt2" Text="2" FontWeight="Bold" FontSize="14" Foreground="#FFB36B" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                      </Border>
                      <TextBlock Text="Boost" FontSize="16" FontWeight="SemiBold" Margin="0,12,0,0"/>
                      <TextBlock Text="Apply Quick Boost - Competitive is recommended. Then restart your PC." FontSize="12.5" Foreground="#9AA5BF" TextWrapping="Wrap" Margin="0,4,0,0"/>
                    </StackPanel>
                  </DockPanel>
                </Border>
                <Border x:Name="BenchStep3" Style="{StaticResource Card}" Margin="6,0,0,0" Padding="20,18">
                  <DockPanel>
                    <StackPanel DockPanel.Dock="Bottom" Margin="0,14,0,0">
                      <Button x:Name="BtnBench3" Style="{StaticResource PrimaryBtn}" Content="Start measuring" HorizontalAlignment="Left"/>
                      <TextBlock x:Name="BenchS3" Text="" FontSize="12" Foreground="#7F8BA6" Margin="0,10,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                    <StackPanel>
                      <Border x:Name="BenchNum3" Width="32" Height="32" CornerRadius="16" Background="#24FF8A1F" BorderBrush="#59FF8A1F" BorderThickness="1" HorizontalAlignment="Left">
                        <TextBlock x:Name="BenchNumTxt3" Text="3" FontWeight="Bold" FontSize="14" Foreground="#FFB36B" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                      </Border>
                      <TextBlock Text="Measure after" FontSize="16" FontWeight="SemiBold" Margin="0,12,0,0"/>
                      <TextBlock Text="Play the same game, same mode and same settings for 2 minutes." FontSize="12.5" Foreground="#9AA5BF" TextWrapping="Wrap" Margin="0,4,0,0"/>
                    </StackPanel>
                  </DockPanel>
                </Border>
              </UniformGrid>
              <Border x:Name="BenchLive" Style="{StaticResource Card}" Margin="0,14,0,0" Padding="20,16" Visibility="Collapsed">
                <StackPanel>
                  <DockPanel>
                    <Button x:Name="BtnBenchStop" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" Content="Stop now" Padding="12,6"/>
                    <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                      <Ellipse x:Name="BenchDot" Width="9" Height="9" Fill="#2ED47A" VerticalAlignment="Center" Margin="0,0,10,0"/>
                      <TextBlock x:Name="BenchLiveTxt" Text="" FontSize="14" FontWeight="SemiBold" VerticalAlignment="Center"/>
                    </StackPanel>
                  </DockPanel>
                  <ProgressBar x:Name="BenchProg" Height="6" Margin="0,14,0,0" Minimum="0" Maximum="120" Value="0" Foreground="#FF8A1F" Background="#1A2440" BorderThickness="0"/>
                  <TextBlock x:Name="BenchLiveSub" Text="" FontSize="12" Foreground="#7F8BA6" Margin="0,8,0,0" TextWrapping="Wrap"/>
                </StackPanel>
              </Border>
              <Border x:Name="BenchResult" Margin="0,14,0,0" CornerRadius="16" Background="#111A2E" BorderBrush="#26334F" BorderThickness="1" Padding="26,22" Visibility="Collapsed">
                <StackPanel>
                  <DockPanel>
                    <TextBlock x:Name="BenchDate" DockPanel.Dock="Right" Text="" FontSize="12" Foreground="#7F8BA6" VerticalAlignment="Center"/>
                    <StackPanel Orientation="Horizontal">
                      <Border Width="30" Height="30" CornerRadius="9" VerticalAlignment="Center">
                        <Border.Background>
                          <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                            <GradientStop Color="#FFB347" Offset="0"/>
                            <GradientStop Color="#FF6A00" Offset="1"/>
                          </LinearGradientBrush>
                        </Border.Background>
                        <TextBlock Text="S" FontWeight="Black" FontSize="16" Foreground="#0A0F1C" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                      </Border>
                      <StackPanel Margin="12,0,0,0" VerticalAlignment="Center">
                        <TextBlock Text="SILVAN BOOST BENCHMARK" FontSize="11" FontWeight="Bold" Foreground="#FFB36B"/>
                        <TextBlock x:Name="BenchGame" Text="" FontSize="18" FontWeight="SemiBold"/>
                      </StackPanel>
                    </StackPanel>
                  </DockPanel>
                  <UniformGrid x:Name="BenchTiles" Columns="3" Margin="0,18,0,0"/>
                  <TextBlock x:Name="BenchVerdict" Text="" FontSize="14" Foreground="#C3CBDD" TextWrapping="Wrap" Margin="0,16,0,0"/>
                  <TextBlock x:Name="BenchSpecs" Text="" FontSize="11.5" Foreground="#7F8BA6" Margin="0,8,0,0" TextWrapping="Wrap"/>
                </StackPanel>
              </Border>
              <StackPanel x:Name="BenchActions" Orientation="Horizontal" Margin="0,12,0,0" Visibility="Collapsed">
                <Button x:Name="BtnBenchSave" Style="{StaticResource PrimaryBtn}" Content="Save as image"/>
                <Button x:Name="BtnBenchReset" Style="{StaticResource GhostBtn}" Content="Start over" Margin="8,0,0,0"/>
              </StackPanel>
              <Border Style="{StaticResource Card}" Margin="0,14,0,0" Padding="18,14">
                <StackPanel>
                  <TextBlock Text="TIPS FOR A FAIR TEST" Style="{StaticResource Label}"/>
                  <TextBlock Text="Use the same game, map or mode and the same in-game settings both times. Practice range or creative mode works best. Silvan Boost must stay open (minimized is fine). Measuring starts as soon as the game is detected - nothing is injected into the game." FontSize="12.5" Foreground="#A9B3CC" TextWrapping="Wrap" Margin="0,8,0,0"/>
                </StackPanel>
              </Border>
            </StackPanel>
          </ScrollViewer>

          <!-- PING BOOSTER -->
          <ScrollViewer x:Name="PagePing" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel Margin="28,6,28,24">
              <DockPanel>
                <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                  <Button x:Name="BtnPingTest" Style="{StaticResource GhostBtn}" Margin="0,0,8,0">
                    <StackPanel Orientation="Horizontal">
                      <TextBlock Text="&#xE9D9;" FontFamily="{StaticResource IconFont}" FontSize="13" VerticalAlignment="Center" Margin="0,0,8,0"/>
                      <TextBlock Text="Run full test"/>
                    </StackPanel>
                  </Button>
                  <Button x:Name="BtnPingBoost" Style="{StaticResource PrimaryBtn}">
                    <StackPanel Orientation="Horizontal">
                      <TextBlock Text="&#xE945;" FontFamily="{StaticResource IconFont}" FontSize="13" VerticalAlignment="Center" Margin="0,0,8,0"/>
                      <TextBlock Text="Boost ping"/>
                    </StackPanel>
                  </Button>
                </StackPanel>
                <StackPanel>
                  <TextBlock Text="Ping Booster" Style="{StaticResource H1}"/>
                  <TextBlock Text="Live connection quality, game server test, bufferbloat test, DNS benchmark and every network optimization in one place." Style="{StaticResource Sub}"/>
                </StackPanel>
              </DockPanel>
              <UniformGrid Columns="5" Margin="0,18,0,0">
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="PING" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="PgPing" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="PgPingSub" Text="to 1.1.1.1" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="JITTER" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="PgJit" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="PgJitSub" Text="ping variation" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="PACKET LOSS" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="PgLoss" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="PgLossSub" Text="last 60 seconds" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="ROUTER" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="PgGw" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="PgGwSub" Text="your home network" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="CONNECTION" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="PgConn" Text="-" FontSize="24" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="PgConnSub" Text="" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
              </UniformGrid>
              <Border Style="{StaticResource Card}" Margin="0,0,10,14">
                <StackPanel>
                  <DockPanel>
                    <TextBlock x:Name="PingGraphMax" DockPanel.Dock="Right" Text="" FontSize="11" Foreground="#7F8BA6"/>
                    <StackPanel Orientation="Horizontal">
                      <TextBlock Text="LIVE PING - LAST 60 SECONDS" Style="{StaticResource Label}"/>
                      <Ellipse Width="8" Height="8" Fill="#FF8A1F" Margin="14,0,5,0" VerticalAlignment="Center"/>
                      <TextBlock Text="internet" FontSize="11" Foreground="#9AA5BF"/>
                      <Ellipse Width="8" Height="8" Fill="#3B82F6" Margin="12,0,5,0" VerticalAlignment="Center"/>
                      <TextBlock Text="your router" FontSize="11" Foreground="#9AA5BF"/>
                    </StackPanel>
                  </DockPanel>
                  <Canvas x:Name="PingGraph" Height="110" Margin="0,10,0,0" ClipToBounds="True">
                    <Polyline x:Name="PingLineGw" Stroke="#3B82F6" StrokeThickness="2" StrokeLineJoin="Round"/>
                    <Polyline x:Name="PingLineNet" Stroke="#FF8A1F" StrokeThickness="2" StrokeLineJoin="Round"/>
                  </Canvas>
                </StackPanel>
              </Border>
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="1.3*"/>
                  <ColumnDefinition Width="14"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <StackPanel>
                  <TextBlock Text="What to do" Style="{StaticResource SectionTitle}" Margin="2,0,0,10"/>
                  <StackPanel x:Name="PingRecList"/>
                  <Border Style="{StaticResource Card}" Margin="0,4,0,0">
                    <StackPanel>
                      <TextBlock Text="Network optimizations" Style="{StaticResource SectionTitle}"/>
                      <StackPanel x:Name="PingTweakList" Margin="0,8,0,0"/>
                    </StackPanel>
                  </Border>
                </StackPanel>
                <StackPanel Grid.Column="2" Margin="0,0,10,0">
                  <Border Style="{StaticResource Card}" Margin="0,0,0,12">
                    <StackPanel>
                      <TextBlock Text="BUFFERBLOAT (PING UNDER LOAD)" Style="{StaticResource Label}"/>
                      <DockPanel Margin="0,8,0,0">
                        <TextBlock x:Name="BbGrade" DockPanel.Dock="Left" Text="-" FontSize="46" FontWeight="Black" Foreground="#9AA5BF" Width="84" VerticalAlignment="Center"/>
                        <StackPanel VerticalAlignment="Center">
                          <TextBlock x:Name="BbIdle" Text="Run the full test" FontSize="12.5"/>
                          <TextBlock x:Name="BbLoad" Text="" FontSize="12.5" Margin="0,3,0,0"/>
                          <TextBlock x:Name="BbSpeed" Text="" FontSize="12.5" Foreground="#9AA5BF" Margin="0,3,0,0"/>
                        </StackPanel>
                      </DockPanel>
                      <TextBlock x:Name="BbNote" Text="Bufferbloat = how much your ping rises while the connection is busy. It is the #1 cause of lag spikes at home." TextWrapping="Wrap" FontSize="11.5" Foreground="#7F8BA6" Margin="0,10,0,0"/>
                    </StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Margin="0,0,0,12">
                    <StackPanel>
                      <TextBlock Text="GAME SERVER REGIONS" Style="{StaticResource Label}"/>
                      <TextBlock Text="Ping to the data centers many online games use." FontSize="11.5" Foreground="#7F8BA6" Margin="0,4,0,8"/>
                      <StackPanel x:Name="RegionList"><TextBlock Text="Run the full test to measure." Foreground="#9AA5BF" FontSize="12.5"/></StackPanel>
                    </StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}">
                    <StackPanel>
                      <DockPanel>
                        <Button x:Name="BtnDnsReset" DockPanel.Dock="Right" Style="{StaticResource SmallBtn}" Content="Reset to automatic"/>
                        <TextBlock Text="DNS BENCHMARK" Style="{StaticResource Label}" VerticalAlignment="Center"/>
                      </DockPanel>
                      <StackPanel x:Name="DnsList" Margin="0,8,0,0"><TextBlock Text="Run the full test to compare DNS servers." Foreground="#9AA5BF" FontSize="12.5"/></StackPanel>
                    </StackPanel>
                  </Border>
                </StackPanel>
              </Grid>
              <TextBlock Text="Ping tools" Style="{StaticResource SectionTitle}" Margin="2,10,0,10"/>
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="14"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <StackPanel>
                  <Border Style="{StaticResource Card}" Margin="0,0,0,12">
                    <StackPanel>
                      <DockPanel>
                        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top" Margin="10,0,0,0"><Button x:Name="BtnRoute" Style="{StaticResource SmallBtn}" Content="Trace route"/></StackPanel>
                        <StackPanel>
                          <TextBlock Text="Find the lag (route analysis)" Style="{StaticResource SectionTitle}"/>
                          <TextBlock Text="Measures every station between your PC and the internet and shows WHERE the delay or packet loss starts: your home network, your provider or the internet." Style="{StaticResource Sub}"/>
                        </StackPanel>
                      </DockPanel>
                      <TextBlock x:Name="RouteSum" Text="" TextWrapping="Wrap" FontSize="12.5" Foreground="#A9B3CC" Margin="0,10,0,0"/>
                      <StackPanel x:Name="RouteList" Margin="0,8,0,0"/>
                    </StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Margin="0,0,0,12">
                    <StackPanel>
                      <DockPanel>
                        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top" Margin="10,0,0,0"><Button x:Name="BtnValve" Style="{StaticResource SmallBtn}" Content="Test servers"/></StackPanel>
                        <StackPanel>
                          <TextBlock Text="CS2 / Valve server ping" Style="{StaticResource SectionTitle}"/>
                          <TextBlock Text="Pings every Valve data center (CS2, Deadlock, Dota 2) and shows the closest ones." Style="{StaticResource Sub}"/>
                        </StackPanel>
                      </DockPanel>
                      <TextBlock x:Name="ValveSum" Text="" TextWrapping="Wrap" FontSize="12.5" Foreground="#A9B3CC" Margin="0,10,0,0"/>
                      <StackPanel x:Name="ValveList" Margin="0,8,0,0"/>
                    </StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Margin="0,0,0,12">
                    <StackPanel>
                      <DockPanel>
                        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top" Margin="10,0,0,0"><Button x:Name="BtnMtuReset" Style="{StaticResource GhostBtn}" Content="Reset" Visibility="Collapsed" Padding="10,5" FontSize="12" Margin="0,0,6,0"/><Button x:Name="BtnMtuApply" Style="{StaticResource GhostBtn}" Content="Apply" Visibility="Collapsed" Padding="10,5" FontSize="12" Margin="0,0,6,0"/><Button x:Name="BtnMtu" Style="{StaticResource SmallBtn}" Content="Run test"/></StackPanel>
                        <StackPanel>
                          <TextBlock Text="MTU test" Style="{StaticResource SectionTitle}"/>
                          <TextBlock Text="Finds the biggest packet your connection can carry. DSL and some fiber lines need a smaller MTU to avoid split packets." Style="{StaticResource Sub}"/>
                        </StackPanel>
                      </DockPanel>
                      <TextBlock x:Name="MtuRes" Text="" TextWrapping="Wrap" FontSize="12.5" Foreground="#A9B3CC" Margin="0,10,0,0"/>
                    </StackPanel>
                  </Border>
                </StackPanel>
                <StackPanel Grid.Column="2" Margin="0,0,10,0">
                  <Border Style="{StaticResource Card}" Margin="0,0,0,12">
                    <StackPanel>
                      <DockPanel>
                        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top" Margin="10,0,0,0"><Button x:Name="BtnBw" Style="{StaticResource SmallBtn}" Content="Scan now"/></StackPanel>
                        <StackPanel>
                          <TextBlock Text="Apps using your internet" Style="{StaticResource SectionTitle}"/>
                          <TextBlock Text="Shows which programs are connected to the internet right now and how busy they are - close the ones that eat your bandwidth." Style="{StaticResource Sub}"/>
                        </StackPanel>
                      </DockPanel>
                      <TextBlock x:Name="BwSum" Text="" TextWrapping="Wrap" FontSize="12.5" Foreground="#A9B3CC" Margin="0,10,0,0"/>
                      <StackPanel x:Name="BwList" Margin="0,8,0,0"/>
                    </StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Margin="0,0,0,12">
                    <StackPanel>
                      <DockPanel>
                        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top" Margin="10,0,0,0"></StackPanel>
                        <StackPanel>
                          <TextBlock Text="Game Network Mode" Style="{StaticResource SectionTitle}"/>
                          <TextBlock Text="When the Live Monitor detects a game, Windows Update downloads (BITS, Delivery Optimization) and OneDrive are paused - and resumed when you close the game." Style="{StaticResource Sub}"/>
                        </StackPanel>
                      </DockPanel>
                      <DockPanel Margin="0,12,0,0">
                        <CheckBox x:Name="GameNetToggle" DockPanel.Dock="Right" Style="{StaticResource Toggle}" VerticalAlignment="Center"/>
                        <TextBlock Text="Pause background downloads while a game runs" FontWeight="SemiBold" VerticalAlignment="Center"/>
                      </DockPanel>
                      <TextBlock x:Name="GameNetRes" Text="" TextWrapping="Wrap" FontSize="12.5" Foreground="#A9B3CC" Margin="0,10,0,0"/>
                    </StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Margin="0,0,0,12">
                    <StackPanel>
                      <DockPanel>
                        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top" Margin="10,0,0,0"><Button x:Name="BtnWifiScan" Style="{StaticResource SmallBtn}" Content="Scan Wi-Fi"/></StackPanel>
                        <StackPanel>
                          <TextBlock Text="Wi-Fi channel check" Style="{StaticResource SectionTitle}"/>
                          <TextBlock Text="Scans nearby Wi-Fi networks and tells you which channel is the least crowded for your router." Style="{StaticResource Sub}"/>
                        </StackPanel>
                      </DockPanel>
                      <TextBlock x:Name="WifiSum" Text="" TextWrapping="Wrap" FontSize="12.5" Foreground="#A9B3CC" Margin="0,10,0,0"/>
                      <StackPanel x:Name="WifiList" Margin="0,8,0,0"/>
                    </StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Margin="0,0,0,12">
                    <StackPanel>
                      <DockPanel>
                        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top" Margin="10,0,0,0"><Button x:Name="BtnNetReset" Style="{StaticResource GhostBtn}" Content="Full reset" Padding="10,5" FontSize="12" Margin="0,0,6,0"/><Button x:Name="BtnNetQuick" Style="{StaticResource SmallBtn}" Content="Quick fix"/></StackPanel>
                        <StackPanel>
                          <TextBlock Text="Network repair" Style="{StaticResource SectionTitle}"/>
                          <TextBlock Text="Fix a broken or slow connection. Quick fix is harmless; full reset restores Windows network defaults (restart needed)." Style="{StaticResource Sub}"/>
                        </StackPanel>
                      </DockPanel>
                      <TextBlock x:Name="NetFixRes" Text="" TextWrapping="Wrap" FontSize="12.5" Foreground="#A9B3CC" Margin="0,10,0,0"/>
                    </StackPanel>
                  </Border>
                </StackPanel>
              </Grid>
            </StackPanel>
          </ScrollViewer>

          <!-- INPUT LAG -->
          <ScrollViewer x:Name="PageInput" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel Margin="28,6,28,24">
              <DockPanel>
                <Button x:Name="BtnInputMax" DockPanel.Dock="Right" Style="{StaticResource PrimaryBtn}" VerticalAlignment="Center">
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="&#xE945;" FontFamily="{StaticResource IconFont}" FontSize="13" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBlock Text="Max input response"/>
                  </StackPanel>
                </Button>
                <StackPanel>
                  <TextBlock Text="Input Lag" Style="{StaticResource H1}"/>
                  <TextBlock Text="Get every click and mouse movement onto the screen as fast as possible." Style="{StaticResource Sub}"/>
                </StackPanel>
              </DockPanel>
              <UniformGrid Columns="4" Margin="0,18,0,0">
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="MOUSE POLLING RATE" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="InPoll" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="InPollSub" Text="not tested yet" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="REFRESH RATE" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="InHz" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="InHzSub" Text="" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="INPUT OPTIMIZATIONS" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="InTw" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="InTwSub" Text="" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="PC LATENCY" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="InLat" Text="-" FontSize="28" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="InLatSub" Text="start a game to measure" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
              </UniformGrid>
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="1.2*"/>
                  <ColumnDefinition Width="14"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <StackPanel>
                  <Border Style="{StaticResource Card}" Margin="0,0,0,14">
                    <StackPanel>
                      <TextBlock Text="MOUSE POLLING RATE TEST" Style="{StaticResource Label}"/>
                      <DockPanel Margin="0,8,0,0">
                        <Button x:Name="BtnPollTest" DockPanel.Dock="Right" Style="{StaticResource PrimaryBtn}" Content="Start test" VerticalAlignment="Center"/>
                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                          <TextBlock x:Name="PollBig" Text="-" FontSize="44" FontWeight="Black" Foreground="#FF9A3C"/>
                          <TextBlock Text="Hz" FontSize="16" Foreground="#9AA5BF" VerticalAlignment="Bottom" Margin="6,0,0,10"/>
                        </StackPanel>
                      </DockPanel>
                      <TextBlock x:Name="PollHint" Text="Click Start, then move your mouse fast in circles for 5 seconds." TextWrapping="Wrap" FontSize="12.5" Foreground="#A9B3CC" Margin="0,6,0,0"/>
                    </StackPanel>
                  </Border>
                  <TextBlock Text="Checklist" Style="{StaticResource SectionTitle}" Margin="2,0,0,10"/>
                  <StackPanel x:Name="InputRecList"/>
                  <Border Style="{StaticResource Card}" Margin="0,4,0,0">
                    <StackPanel>
                      <TextBlock Text="Input optimizations" Style="{StaticResource SectionTitle}"/>
                      <StackPanel x:Name="InputTweakList" Margin="0,8,0,0"/>
                    </StackPanel>
                  </Border>
                </StackPanel>
                <StackPanel Grid.Column="2" Margin="0,0,10,0">
                  <TextBlock Text="Driver &amp; game settings" Style="{StaticResource SectionTitle}" Margin="2,0,0,10"/>
                  <StackPanel x:Name="InputGuideList"/>
                  <Border Style="{StaticResource Card}">
                    <StackPanel>
                      <TextBlock Text="WHAT THE NUMBERS MEAN" Style="{StaticResource Label}"/>
                      <TextBlock TextWrapping="Wrap" FontSize="12.5" Foreground="#A9B3CC" Margin="0,8,0,0" Text="PC latency is the time from your click or mouse movement reaching the PC until the new image is shown - measured live in-game with Intel PresentMon. Under 25 ms is excellent. Your mouse and monitor add a few ms on top. Polling rate is how often your mouse reports its position: 1000 Hz = every 1 ms."/>
                    </StackPanel>
                  </Border>
                </StackPanel>
              </Grid>
            </StackPanel>
          </ScrollViewer>

          <!-- PROCESS REDUCER -->
          <ScrollViewer x:Name="PageProc" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel Margin="28,6,28,24">
              <DockPanel>
                <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                  <Button x:Name="BtnProcRefresh" Style="{StaticResource GhostBtn}" Margin="0,0,8,0">
                    <StackPanel Orientation="Horizontal">
                      <TextBlock Text="&#xE72C;" FontFamily="{StaticResource IconFont}" FontSize="13" VerticalAlignment="Center" Margin="0,0,8,0"/>
                      <TextBlock Text="Refresh"/>
                    </StackPanel>
                  </Button>
                  <Button x:Name="BtnProcReduce" Style="{StaticResource PrimaryBtn}">
                    <StackPanel Orientation="Horizontal">
                      <TextBlock Text="&#xE945;" FontFamily="{StaticResource IconFont}" FontSize="13" VerticalAlignment="Center" Margin="0,0,8,0"/>
                      <TextBlock Text="Reduce processes"/>
                    </StackPanel>
                  </Button>
                </StackPanel>
                <StackPanel>
                  <TextBlock Text="Process Reducer" Style="{StaticResource H1}"/>
                  <TextBlock x:Name="ProcSub" Text="" Style="{StaticResource Sub}"/>
                </StackPanel>
              </DockPanel>
              <UniformGrid Columns="4" Margin="0,18,0,4">
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="PROCESSES" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="PcProc" Text="-" FontSize="30" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="PcProcSub" Text="running right now" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="SERVICES RUNNING" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="PcSvc" Text="-" FontSize="30" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="PcSvcSub" Text="Windows services" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="SVCHOST PROCESSES" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="PcSvch" Text="-" FontSize="30" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="PcSvchSub" Text="service host processes" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="0,0,10,10" Padding="16,14">
                  <StackPanel>
                    <TextBlock Text="THREADS" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="PcThr" Text="-" FontSize="30" FontWeight="Bold" Margin="0,6,0,0"/>
                    <TextBlock x:Name="PcThrSub" Text="across all processes" FontSize="11.5" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                </Border>
              </UniformGrid>
              <Border Background="#16213A" CornerRadius="10" Padding="14,10" Margin="0,0,10,14">
                <StackPanel Orientation="Horizontal">
                  <TextBlock Text="&#xE946;" FontFamily="{StaticResource IconFont}" FontSize="14" Foreground="#7AA7FF" VerticalAlignment="Center" Margin="0,0,10,0"/>
                  <TextBlock Text="Reduce processes = turns off unneeded services and background features, groups Windows services and closes the apps switched on below. Windows itself always needs around 100+ processes - those are protected and never touched." Foreground="#A9B3CC" FontSize="12.5" TextWrapping="Wrap" VerticalAlignment="Center"/>
                </StackPanel>
              </Border>
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="14"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Border Style="{StaticResource Card}" VerticalAlignment="Top">
                  <StackPanel>
                    <DockPanel>
                      <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
                        <Button x:Name="BtnProcSelRec" Style="{StaticResource GhostBtn}" Content="Recommended" Padding="10,5" FontSize="12" Margin="0,0,6,0"/>
                        <Button x:Name="BtnProcClose" Style="{StaticResource SmallBtn}" Content="Close selected (0)"/>
                      </StackPanel>
                      <TextBlock Text="Running apps you can close" Style="{StaticResource SectionTitle}" VerticalAlignment="Center"/>
                    </DockPanel>
                    <TextBlock Text="Windows, drivers, anti-cheat and the game you are playing are hidden and protected." Foreground="#9AA5BF" FontSize="12" Margin="0,4,0,8" TextWrapping="Wrap"/>
                    <StackPanel x:Name="ProcList"/>
                  </StackPanel>
                </Border>
                <Border Grid.Column="2" Style="{StaticResource Card}" VerticalAlignment="Top" Margin="0,0,10,0">
                  <StackPanel>
                    <TextBlock Text="Startup apps" Style="{StaticResource SectionTitle}"/>
                    <TextBlock x:Name="StartSub" Text="" Foreground="#9AA5BF" FontSize="12" Margin="0,4,0,8" TextWrapping="Wrap"/>
                    <StackPanel x:Name="StartList"/>
                  </StackPanel>
                </Border>
              </Grid>
            </StackPanel>
          </ScrollViewer>

          <!-- APPS -->
          <Grid x:Name="PageApps" Visibility="Collapsed" Margin="28,6,16,0">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="*"/>
            </Grid.RowDefinitions>
            <DockPanel Margin="0,0,12,0">
              <StackPanel x:Name="AppsBloatBtns" DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                <Button x:Name="BtnAppsNone" Style="{StaticResource GhostBtn}" Content="Select none" Margin="0,0,8,0"/>
                <Button x:Name="BtnAppsRec" Style="{StaticResource GhostBtn}" Content="Select recommended" Margin="0,0,8,0"/>
                <Button x:Name="BtnAppsRemove" Style="{StaticResource PrimaryBtn}" Content="Remove selected (0)"/>
              </StackPanel>
              <StackPanel>
                <TextBlock Text="Apps" Style="{StaticResource H1}"/>
                <TextBlock x:Name="AppsSub" Text="" Style="{StaticResource Sub}"/>
              </StackPanel>
            </DockPanel>
            <WrapPanel Grid.Row="1" Margin="0,16,12,6">
              <RadioButton x:Name="AppTabBloat" Content="Bloatware cleaner" GroupName="apptab" Style="{StaticResource Chip}" Margin="0,0,8,8" IsChecked="True"/>
              <RadioButton x:Name="AppTabAll" Content="All installed apps" GroupName="apptab" Style="{StaticResource Chip}" Margin="0,0,8,8"/>
              <RadioButton x:Name="AppTabRec" Content="Recommended downloads" GroupName="apptab" Style="{StaticResource Chip}" Margin="0,0,8,8"/>
            </WrapPanel>
            <Grid Grid.Row="2">
              <!-- bloatware -->
              <Grid x:Name="AppsBloatView">
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <Border Background="#16213A" CornerRadius="10" Padding="14,10" Margin="0,4,12,14">
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="&#xE946;" FontFamily="{StaticResource IconFont}" FontSize="14" Foreground="#7AA7FF" VerticalAlignment="Center" Margin="0,0,10,0"/>
                    <TextBlock Text="Only preinstalled apps that are on this PC are shown. Switch on every app you want to remove - removed apps can be reinstalled from the Microsoft Store." Foreground="#A9B3CC" FontSize="12.5" TextWrapping="Wrap" VerticalAlignment="Center"/>
                  </StackPanel>
                </Border>
                <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                  <UniformGrid x:Name="AppList" Columns="2" VerticalAlignment="Top" Margin="0,0,4,20"/>
                </ScrollViewer>
              </Grid>
              <!-- all installed -->
              <Grid x:Name="AppsAllView" Visibility="Collapsed">
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <DockPanel Margin="0,4,12,0">
                  <Button x:Name="BtnAppsRefresh" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" Content="Refresh" Margin="12,0,0,8" VerticalAlignment="Top"/>
                  <TextBox x:Name="AppSearch" Tag="Search apps or publishers..." DockPanel.Dock="Right" Width="260" Height="36" Style="{StaticResource Search}" VerticalAlignment="Top" Margin="12,0,0,8"/>
                  <WrapPanel>
                    <RadioButton x:Name="AppFltAll" Content="All" GroupName="appflt" Style="{StaticResource Chip}" Margin="0,0,8,8" IsChecked="True"/>
                    <RadioButton x:Name="AppFltProg" Content="Programs" GroupName="appflt" Style="{StaticResource Chip}" Margin="0,0,8,8"/>
                    <RadioButton x:Name="AppFltStore" Content="Store apps" GroupName="appflt" Style="{StaticResource Chip}" Margin="0,0,8,8"/>
                    <Border Width="1" Height="22" Background="#2A3858" Margin="4,0,12,8" VerticalAlignment="Center"/>
                    <RadioButton x:Name="AppSortName" Content="Sort: name" GroupName="appsort" Style="{StaticResource Chip}" Margin="0,0,8,8" IsChecked="True"/>
                    <RadioButton x:Name="AppSortSize" Content="Sort: size" GroupName="appsort" Style="{StaticResource Chip}" Margin="0,0,8,8"/>
                    <RadioButton x:Name="AppSortDate" Content="Sort: newest" GroupName="appsort" Style="{StaticResource Chip}" Margin="0,0,8,8"/>
                  </WrapPanel>
                </DockPanel>
                <TextBlock x:Name="AppsAllSum" Grid.Row="1" Text="" Foreground="#9AA5BF" FontSize="12" Margin="2,2,0,10"/>
                <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                  <Border Style="{StaticResource Card}" Margin="0,0,12,20" Padding="16,4">
                    <StackPanel x:Name="InstList"/>
                  </Border>
                </ScrollViewer>
              </Grid>
              <!-- recommended -->
              <ScrollViewer x:Name="AppsRecView" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                <StackPanel Margin="0,4,4,20">
                  <Border Background="#16213A" CornerRadius="10" Padding="14,10" Margin="0,0,12,14">
                    <StackPanel Orientation="Horizontal">
                      <TextBlock Text="&#xE946;" FontFamily="{StaticResource IconFont}" FontSize="14" Foreground="#7AA7FF" VerticalAlignment="Center" Margin="0,0,10,0"/>
                      <TextBlock x:Name="RecNote" Text="" Foreground="#A9B3CC" FontSize="12.5" TextWrapping="Wrap" VerticalAlignment="Center"/>
                    </StackPanel>
                  </Border>
                  <UniformGrid x:Name="RecGrid" Columns="3" VerticalAlignment="Top"/>
                </StackPanel>
              </ScrollViewer>
            </Grid>
          </Grid>

          <!-- BACKUP -->
          <ScrollViewer x:Name="PageBackup" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel Margin="28,6,28,24">
              <TextBlock Text="Backup &amp; Restore" Style="{StaticResource H1}"/>
              <TextBlock Text="Every change Silvan Boost makes is recorded, so you can always go back." Style="{StaticResource Sub}"/>
              <UniformGrid Columns="3" Margin="0,20,0,0">
                <Border Style="{StaticResource Card}" Margin="0,0,10,0">
                  <DockPanel>
                    <StackPanel DockPanel.Dock="Bottom" Margin="0,16,0,0">
                      <Button x:Name="BpCreate" Style="{StaticResource PrimaryBtn}" Content="Create restore point"/>
                      <Button x:Name="BpOpenRestore" Style="{StaticResource GhostBtn}" Content="Open System Restore" Margin="0,8,0,0"/>
                    </StackPanel>
                    <StackPanel>
                      <TextBlock Text="&#xE81C;" Style="{StaticResource Icon}" HorizontalAlignment="Left" FontSize="22" Foreground="#FF8A1F"/>
                      <TextBlock Text="System Restore point" Style="{StaticResource SectionTitle}" Margin="0,12,0,0"/>
                      <TextBlock x:Name="RpInfo" Text="" Style="{StaticResource Sub}"/>
                    </StackPanel>
                  </DockPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="5,0,5,0">
                  <DockPanel>
                    <Button x:Name="BpRevertAll" DockPanel.Dock="Bottom" Style="{StaticResource GhostBtn}" Content="Revert all optimizations" Margin="0,16,0,0"/>
                    <StackPanel>
                      <TextBlock Text="&#xE7A7;" Style="{StaticResource Icon}" HorizontalAlignment="Left" FontSize="22" Foreground="#FF8A1F"/>
                      <TextBlock Text="Undo everything" Style="{StaticResource SectionTitle}" Margin="0,12,0,0"/>
                      <TextBlock Text="Puts every active optimization back to the exact value your PC had before. Removed apps can be reinstalled from the Microsoft Store." Style="{StaticResource Sub}"/>
                    </StackPanel>
                  </DockPanel>
                </Border>
                <Border Style="{StaticResource Card}" Margin="10,0,0,0">
                  <DockPanel>
                    <Button x:Name="BpOpenFolder" DockPanel.Dock="Bottom" Style="{StaticResource GhostBtn}" Content="Open backup folder" Margin="0,16,0,0"/>
                    <StackPanel>
                      <TextBlock Text="&#xE8B7;" Style="{StaticResource Icon}" HorizontalAlignment="Left" FontSize="22" Foreground="#FF8A1F"/>
                      <TextBlock Text="Silvan Boost backup" Style="{StaticResource SectionTitle}" Margin="0,12,0,0"/>
                      <TextBlock x:Name="BackupInfo" Text="" Style="{StaticResource Sub}"/>
                    </StackPanel>
                  </DockPanel>
                </Border>
              </UniformGrid>
              <Border Style="{StaticResource Card}" Margin="0,14,0,0">
                <DockPanel>
                  <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                    <Button x:Name="BtnExport" Style="{StaticResource GhostBtn}" Content="Export my setup" Margin="0,0,8,0"/>
                    <Button x:Name="BtnImport" Style="{StaticResource PrimaryBtn}" Content="Import a setup"/>
                  </StackPanel>
                  <StackPanel>
                    <TextBlock Text="Share your setup" Style="{StaticResource SectionTitle}"/>
                    <TextBlock Text="Save your optimizations and macros as a file and send it to a friend - they load it with one click. Only safe optimizations are imported, and a restore point is made first." Style="{StaticResource Sub}"/>
                  </StackPanel>
                </DockPanel>
              </Border>
              <Border Style="{StaticResource Card}" Margin="0,14,0,0">
                <StackPanel>
                  <TextBlock Text="Activity log" Style="{StaticResource SectionTitle}"/>
                  <TextBlock x:Name="LogView" Text="" FontFamily="Consolas" FontSize="12" Foreground="#A9B3CC" Margin="0,10,0,0" TextWrapping="Wrap"/>
                </StackPanel>
              </Border>
            </StackPanel>
          </ScrollViewer>

          <!-- ABOUT -->
          <ScrollViewer x:Name="PageAbout" Visibility="Collapsed" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel Margin="28,6,28,24" MaxWidth="820" HorizontalAlignment="Left">
              <TextBlock Text="About Silvan Boost" Style="{StaticResource H1}"/>
              <TextBlock x:Name="AboutVer" Text="" Style="{StaticResource Sub}"/>
              <Border Style="{StaticResource Card}" Margin="0,20,0,0">
                <StackPanel>
                  <DockPanel>
                    <Button x:Name="BtnUpdCheck" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" Content="Check for updates" VerticalAlignment="Top"/>
                    <StackPanel>
                      <TextBlock Text="Updates" Style="{StaticResource SectionTitle}"/>
                      <TextBlock x:Name="UpdStatus" Text="" Style="{StaticResource Sub}"/>
                    </StackPanel>
                  </DockPanel>
                  <DockPanel Margin="0,14,0,0">
                    <CheckBox x:Name="UpdAuto" DockPanel.Dock="Right" Style="{StaticResource Toggle}" VerticalAlignment="Center"/>
                    <StackPanel>
                      <TextBlock Text="Install updates automatically" FontWeight="SemiBold"/>
                      <TextBlock Text="Silvan Boost checks for a new version at every start. When off, it asks first." Foreground="#9AA5BF" FontSize="12" TextWrapping="Wrap"/>
                    </StackPanel>
                  </DockPanel>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Margin="0,14,0,0">
                <StackPanel>
                  <DockPanel>
                    <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                      <RadioButton x:Name="LangDe" Content="Deutsch" GroupName="aboutlang" Style="{StaticResource Chip}" Margin="0,0,6,0"/>
                      <RadioButton x:Name="LangEn" Content="English" GroupName="aboutlang" Style="{StaticResource Chip}"/>
                    </StackPanel>
                    <StackPanel>
                      <TextBlock Text="Language" Style="{StaticResource SectionTitle}"/>
                      <TextBlock Text="Changes all text right away. No restart needed." Foreground="#9AA5BF" FontSize="12" TextWrapping="Wrap"/>
                    </StackPanel>
                  </DockPanel>
                  <DockPanel Margin="0,16,0,0">
                    <Button x:Name="BtnTourAgain" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" Content="Show the tour again" VerticalAlignment="Center"/>
                    <StackPanel>
                      <TextBlock Text="Beginner tour" FontWeight="SemiBold"/>
                      <TextBlock Text="Six short steps, about one minute. Also on the ? button up top." Foreground="#9AA5BF" FontSize="12" TextWrapping="Wrap"/>
                    </StackPanel>
                  </DockPanel>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Margin="0,14,0,0">
                <StackPanel>
                  <DockPanel>
                    <CheckBox x:Name="TrayTg" DockPanel.Dock="Right" Style="{StaticResource Toggle}" VerticalAlignment="Center"/>
                    <StackPanel>
                      <TextBlock Text="Keep running in the tray when closed" FontWeight="SemiBold"/>
                      <TextBlock Text="The X button hides Silvan Boost next to the clock, so auto game mode, macros and the live monitor keep working. Right-click the tray icon to exit." Foreground="#9AA5BF" FontSize="12" TextWrapping="Wrap"/>
                    </StackPanel>
                  </DockPanel>
                  <DockPanel Margin="0,16,0,0">
                    <Button x:Name="BtnReport" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" Content="Report a problem" VerticalAlignment="Center"/>
                    <StackPanel>
                      <TextBlock Text="Something not working?" FontWeight="SemiBold"/>
                      <TextBlock Text="Creates a short report (version, PC parts, activity log) on your desktop and copies it - send it to Silvan." Foreground="#9AA5BF" FontSize="12" TextWrapping="Wrap"/>
                    </StackPanel>
                  </DockPanel>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Margin="0,14,0,0">
                <StackPanel>
                  <TextBlock Text="Adapted to this PC" Style="{StaticResource SectionTitle}"/>
                  <TextBlock x:Name="AboutRig" Style="{StaticResource Sub}" Margin="0,8,0,0" Text="Silvan Boost scans the hardware every time it starts and adapts the optimizations: tweaks that cannot work on this PC are disabled, and tweaks that are a bad idea here are marked and skipped by the presets."/>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Margin="0,14,0,0">
                <StackPanel>
                  <TextBlock Text="What to expect" Style="{StaticResource SectionTitle}"/>
                  <TextBlock Style="{StaticResource Sub}" Margin="0,8,0,0" Text="Windows tweaks mostly improve consistency: fewer stutters, steadier 1% lows, snappier input. The biggest raw FPS gains on a PC like yours come from the PC Scanner checks: XMP/EXPO enabled for your RAM, Resizable BAR on, the monitor at its highest refresh rate, an up-to-date BIOS and NVIDIA driver, and NVIDIA Reflex in-game."/>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Margin="0,14,0,0">
                <StackPanel>
                  <TextBlock Text="Safety" Style="{StaticResource SectionTitle}"/>
                  <TextBlock Style="{StaticResource Sub}" Margin="0,8,0,0" Text="A System Restore point is created before the first change of each session, and every original value is saved to C:\ProgramData\SilvanBoost\backup.json. Silvan Boost deliberately does not disable Microsoft Defender, Windows Update or CPU security mitigations - they cost almost no FPS and protect your PC. Advanced tweaks ask for confirmation first."/>
                </StackPanel>
              </Border>
            </StackPanel>
          </ScrollViewer>

          <!-- Busy overlay -->
          <Grid x:Name="Overlay" Background="#EE0A0F1C" Visibility="Visible">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
              <Border Width="64" Height="64" CornerRadius="18" HorizontalAlignment="Center">
                <Border.Background>
                  <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                    <GradientStop Color="#FFB347" Offset="0"/>
                    <GradientStop Color="#FF6A00" Offset="1"/>
                  </LinearGradientBrush>
                </Border.Background>
                <TextBlock Text="S" FontFamily="Segoe UI Variable Display, Segoe UI" FontWeight="Black" FontSize="36" Foreground="#0A0F1C" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="0,-3,0,0"/>
              </Border>
              <ProgressBar IsIndeterminate="True" Width="240" Height="4" Margin="0,22,0,0" Foreground="#FF8A1F" Background="#1A2440" BorderThickness="0"/>
              <TextBlock x:Name="OverlayText" Text="Scanning your PC..." Margin="0,14,0,0" HorizontalAlignment="Center" FontSize="14" Foreground="#C9D1E3"/>
            </StackPanel>
          </Grid>
        </Grid>

        <!-- Status bar -->
        <Border Grid.Row="2" BorderBrush="#18223A" BorderThickness="0,1,0,0" Background="#0C1324">
          <DockPanel Margin="26,0,12,0">
            <Border x:Name="UpdPill" DockPanel.Dock="Right" Visibility="Collapsed" Background="#26FF8A1F" CornerRadius="8" Padding="4,3" VerticalAlignment="Center" Margin="8,0,0,0">
              <Button x:Name="BtnUpdNow" Style="{StaticResource SmallBtn}" Content="Update available"/>
            </Border>
            <Border x:Name="RebootPill" DockPanel.Dock="Right" Visibility="Collapsed" Background="#1A3B82F6" CornerRadius="8" Padding="10,3" VerticalAlignment="Center">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="Restart needed to finish some optimizations" Foreground="#9EBEFF" FontSize="12" VerticalAlignment="Center"/>
                <Button x:Name="BtnRestart" Style="{StaticResource SmallBtn}" Content="Restart now" Margin="10,0,0,0"/>
              </StackPanel>
            </Border>
            <Ellipse x:Name="StatusDot" Width="8" Height="8" Fill="#2ED47A" Margin="0,0,10,0" VerticalAlignment="Center"/>
            <TextBlock x:Name="StatusText" Text="Starting..." Foreground="#9AA5BF" VerticalAlignment="Center" FontSize="12" TextTrimming="CharacterEllipsis"/>
          </DockPanel>
        </Border>
      </Grid>
      <!-- BEGINNER TOUR -->
      <Grid x:Name="TourLayer" Grid.ColumnSpan="2" Visibility="Collapsed">
        <Path x:Name="TourDim" Fill="#BD050810"/>
        <Canvas x:Name="TourCanvas" ClipToBounds="True">
          <Border x:Name="TourPulse" BorderBrush="#FF8A1F" BorderThickness="2" CornerRadius="11" RenderTransformOrigin="0.5,0.5" IsHitTestVisible="False" Visibility="Collapsed"/>
          <Border x:Name="TourRing" BorderBrush="#FF8A1F" BorderThickness="2" CornerRadius="11" IsHitTestVisible="False" Visibility="Collapsed">
            <Border Margin="-6" BorderBrush="#2EFF8A1F" BorderThickness="4" CornerRadius="15"/>
          </Border>
          <Border x:Name="TourBubble" Width="360" CornerRadius="16" Background="#111A2E" BorderBrush="#2A3858" BorderThickness="1" Padding="20,16,20,18" Visibility="Collapsed">
            <StackPanel>
              <DockPanel>
                <Button x:Name="BtnTourSkip" DockPanel.Dock="Right" Style="{StaticResource SmallBtn}" Content="Skip tour"/>
                <TextBlock x:Name="TourStepTxt" Text="Step 1 of 6" FontSize="12" Foreground="#8C97B0" VerticalAlignment="Center"/>
              </DockPanel>
              <WrapPanel Margin="0,8,0,0">
                <TextBlock x:Name="TourTitle" Text="" FontSize="19" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" Margin="0,0,10,0" VerticalAlignment="Center"/>
                <Border x:Name="TourReco" CornerRadius="11" Background="#1F2ED47A" Padding="9,2" VerticalAlignment="Center" Visibility="Collapsed">
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="&#xE73E;" FontFamily="{StaticResource IconFont}" FontSize="10" Foreground="#5BE39A" VerticalAlignment="Center"/>
                    <TextBlock Text="Recommended" FontSize="11.5" FontWeight="SemiBold" Foreground="#5BE39A" Margin="5,0,0,0"/>
                  </StackPanel>
                </Border>
              </WrapPanel>
              <TextBlock x:Name="TourText" Text="" FontSize="13.5" Foreground="#C3CBDD" TextWrapping="Wrap" Margin="0,6,0,0" LineHeight="20"/>
              <DockPanel Margin="0,18,0,0">
                <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
                  <Button x:Name="BtnTourBack" Style="{StaticResource GhostBtn}" Content="Back" Padding="14,8"/>
                  <Button x:Name="BtnTourNext" Style="{StaticResource PrimaryBtn}" Content="Next" Padding="18,8" Margin="8,0,0,0"/>
                </StackPanel>
                <StackPanel x:Name="TourDots" Orientation="Horizontal" VerticalAlignment="Center"/>
              </DockPanel>
            </StackPanel>
          </Border>
        </Canvas>

        <Grid x:Name="TourWelcome" Background="#BD050810" Visibility="Collapsed">
          <Border x:Name="TourWelcomeCard" Width="520" CornerRadius="20" Background="#111A2E" BorderBrush="#26334F" BorderThickness="1" Padding="40,34,40,26" HorizontalAlignment="Center" VerticalAlignment="Center">
            <StackPanel>
              <Border Width="52" Height="52" CornerRadius="15" HorizontalAlignment="Left">
                <Border.Background>
                  <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                    <GradientStop Color="#FFB347" Offset="0"/>
                    <GradientStop Color="#FF6A00" Offset="1"/>
                  </LinearGradientBrush>
                </Border.Background>
                <TextBlock Text="S" FontFamily="Segoe UI Variable Display, Segoe UI" FontWeight="Black" FontSize="28" Foreground="#0A0F1C" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="0,-2,0,0"/>
              </Border>
              <TextBlock Text="Welcome to Silvan Boost" FontSize="28" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" Margin="0,18,0,0" TextWrapping="Wrap"/>
              <TextBlock Text="Your PC is scanned. A short tour shows you the few buttons that matter most." FontSize="14.5" Foreground="#9AA5BF" TextWrapping="Wrap" Margin="0,8,0,0"/>
              <TextBlock Text="LANGUAGE" Style="{StaticResource Label}" Margin="0,22,0,10"/>
              <UniformGrid Columns="2">
                <RadioButton x:Name="TourLangDe" Style="{StaticResource LangCard}" Margin="0,0,6,0">
                  <StackPanel>
                    <TextBlock Text="DE" FontSize="11.5" FontWeight="Bold" Foreground="#8C97B0"/>
                    <TextBlock Text="Deutsch" FontSize="16" FontWeight="SemiBold" Margin="0,2,0,0"/>
                  </StackPanel>
                </RadioButton>
                <RadioButton x:Name="TourLangEn" Style="{StaticResource LangCard}" Margin="6,0,0,0">
                  <StackPanel>
                    <TextBlock Text="EN" FontSize="11.5" FontWeight="Bold" Foreground="#8C97B0"/>
                    <TextBlock Text="English" FontSize="16" FontWeight="SemiBold" Margin="0,2,0,0"/>
                  </StackPanel>
                </RadioButton>
              </UniformGrid>
              <TextBlock Text="Applies instantly. No restart needed." FontSize="12" Foreground="#7F8BA6" Margin="2,8,0,0"/>
              <StackPanel Orientation="Horizontal" Margin="0,24,0,0">
                <Button x:Name="BtnTourStart" Style="{StaticResource PrimaryBtn}" Content="Start the tour (1 min)" Padding="22,12"/>
                <Button x:Name="BtnTourWelcomeSkip" Style="{StaticResource GhostBtn}" Content="Skip" Padding="20,12" Margin="10,0,0,0"/>
              </StackPanel>
              <TextBlock Text="You can open the tour again any time with the ? button." FontSize="12" Foreground="#7F8BA6" Margin="2,16,0,0" TextWrapping="Wrap"/>
            </StackPanel>
          </Border>
        </Grid>

        <Grid x:Name="TourDone" Background="#BD050810" Visibility="Collapsed">
          <Border x:Name="TourDoneCard" Width="540" CornerRadius="20" Background="#111A2E" BorderBrush="#26334F" BorderThickness="1" Padding="40,34,40,26" HorizontalAlignment="Center" VerticalAlignment="Center">
            <StackPanel>
              <Border x:Name="TourCheck" Width="60" Height="60" CornerRadius="30" Background="#242ED47A" BorderBrush="#802ED47A" BorderThickness="1.5" HorizontalAlignment="Left" RenderTransformOrigin="0.5,0.5">
                <TextBlock Text="&#xE73E;" FontFamily="{StaticResource IconFont}" FontSize="24" Foreground="#2ED47A" HorizontalAlignment="Center" VerticalAlignment="Center"/>
              </Border>
              <TextBlock Text="You're all set" FontSize="28" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" Margin="0,20,0,0"/>
              <TextBlock Text="New here? Do these three things, in this order:" FontSize="14.5" Foreground="#9AA5BF" Margin="0,8,0,18" TextWrapping="Wrap"/>
              <StackPanel x:Name="TourDoneList">
                <Border CornerRadius="12" Background="#0E1526" BorderBrush="#1E2A45" BorderThickness="1" Padding="14,11" Margin="0,0,0,8">
                  <DockPanel>
                    <Border Width="30" Height="30" CornerRadius="15" Background="#24FF8A1F" BorderBrush="#59FF8A1F" BorderThickness="1" VerticalAlignment="Center">
                      <TextBlock Text="1" FontWeight="Bold" FontSize="13.5" Foreground="#FFB36B" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <StackPanel Margin="14,0,0,0">
                      <TextBlock Text="Quick Boost on Competitive" FontSize="14.5" FontWeight="SemiBold"/>
                      <TextBlock Text="Turns on the tweaks most people need." FontSize="12.5" Foreground="#9AA5BF" Margin="0,2,0,0"/>
                    </StackPanel>
                  </DockPanel>
                </Border>
                <Border CornerRadius="12" Background="#0E1526" BorderBrush="#1E2A45" BorderThickness="1" Padding="14,11" Margin="0,0,0,8">
                  <DockPanel>
                    <Border Width="30" Height="30" CornerRadius="15" Background="#24FF8A1F" BorderBrush="#59FF8A1F" BorderThickness="1" VerticalAlignment="Center">
                      <TextBlock Text="2" FontWeight="Bold" FontSize="13.5" Foreground="#FFB36B" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <StackPanel Margin="14,0,0,0">
                      <TextBlock Text="Game Preset for your game" FontSize="14.5" FontWeight="SemiBold"/>
                      <TextBlock Text="Pick your game, then click Optimize." FontSize="12.5" Foreground="#9AA5BF" Margin="0,2,0,0"/>
                    </StackPanel>
                  </DockPanel>
                </Border>
                <Border CornerRadius="12" Background="#0E1526" BorderBrush="#1E2A45" BorderThickness="1" Padding="14,11" Margin="0,0,0,8">
                  <DockPanel>
                    <Border Width="30" Height="30" CornerRadius="15" Background="#24FF8A1F" BorderBrush="#59FF8A1F" BorderThickness="1" VerticalAlignment="Center">
                      <TextBlock Text="3" FontWeight="Bold" FontSize="13.5" Foreground="#FFB36B" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <StackPanel Margin="14,0,0,0">
                      <TextBlock Text="Restart your PC" FontSize="14.5" FontWeight="SemiBold"/>
                      <TextBlock Text="Some changes only apply after a restart." FontSize="12.5" Foreground="#9AA5BF" Margin="0,2,0,0"/>
                    </StackPanel>
                  </DockPanel>
                </Border>
              </StackPanel>
              <DockPanel Margin="0,18,0,0">
                <Button x:Name="BtnTourDoneClose" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" Content="Close" Padding="22,12" Margin="10,0,0,0"/>
                <Button x:Name="BtnTourOpenQuick" Style="{StaticResource PrimaryBtn}" Content="Open Quick Boost" Padding="22,12"/>
              </DockPanel>
              <TextBlock Text="Open the tour again any time with the ? button" FontSize="12" Foreground="#7F8BA6" Margin="0,16,0,0" HorizontalAlignment="Center"/>
            </StackPanel>
          </Border>
        </Grid>
      </Grid>
      <!-- plan ending soon -->
      <Border x:Name="AuthToast" Grid.ColumnSpan="2" HorizontalAlignment="Right" VerticalAlignment="Bottom" Margin="0,0,22,46" MaxWidth="420" CornerRadius="12" Background="#111A2E" BorderBrush="#66FBBF24" BorderThickness="1" Padding="14,12" Visibility="Collapsed">
        <Border.Effect><DropShadowEffect BlurRadius="30" ShadowDepth="8" Direction="270" Opacity="0.4" Color="#000000"/></Border.Effect>
        <DockPanel>
          <Button x:Name="BtnAuthToastX" DockPanel.Dock="Right" Style="{StaticResource TitleBtn}" Content="&#xE8BB;" VerticalAlignment="Top" Margin="6,-10,-12,-10"/>
          <Border Width="32" Height="32" CornerRadius="16" Background="#1FFBBF24" VerticalAlignment="Center">
            <TextBlock Text="&#xE823;" FontFamily="{StaticResource IconFont}" FontSize="15" Foreground="#FBBF24" HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <TextBlock x:Name="AuthToastTxt" Text="" FontSize="13.5" Foreground="#C3CBDD" TextWrapping="Wrap" Margin="12,0,0,0" VerticalAlignment="Center"/>
        </DockPanel>
      </Border>

      <!-- ACCOUNT / LOGIN -->
      <Grid x:Name="AuthLayer" Grid.ColumnSpan="2" Visibility="Visible" Background="#0A0F1C">
        <Border IsHitTestVisible="False">
          <Border.Background>
            <RadialGradientBrush Center="0.5,0.42" GradientOrigin="0.5,0.42" RadiusX="0.55" RadiusY="0.6">
              <GradientStop Color="#1AFF8A1F" Offset="0"/>
              <GradientStop Color="#00FF8A1F" Offset="1"/>
            </RadialGradientBrush>
          </Border.Background>
        </Border>
        <DockPanel VerticalAlignment="Top" Height="44">
          <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
            <Button x:Name="BtnAuthDe" Style="{StaticResource TitleBtn}" FontFamily="Segoe UI" FontSize="12" FontWeight="SemiBold" Content="DE"/>
            <Button x:Name="BtnAuthEn" Style="{StaticResource TitleBtn}" FontFamily="Segoe UI" FontSize="12" FontWeight="SemiBold" Content="EN"/>
            <Button x:Name="BtnAuthMin" Style="{StaticResource TitleBtn}" Content="&#xE921;"/>
            <Button x:Name="BtnAuthClose" Style="{StaticResource CloseBtn}" Content="&#xE8BB;"/>
          </StackPanel>
          <StackPanel Orientation="Horizontal" Margin="18,0,0,0" VerticalAlignment="Center">
            <Image x:Name="AuthLogoSmall" Width="18" Height="18" VerticalAlignment="Center"/>
            <TextBlock Text="Silvan Boost" Foreground="#8C97B0" FontSize="12.5" Margin="9,0,0,0" VerticalAlignment="Center"/>
          </StackPanel>
        </DockPanel>

        <Border x:Name="AuthCard" Width="440" CornerRadius="20" Background="#111A2E" BorderBrush="#2A3858" BorderThickness="1" Padding="34,32,34,26" HorizontalAlignment="Center" VerticalAlignment="Center" RenderTransformOrigin="0.5,0.5">
          <Border.RenderTransform><TranslateTransform Y="0"/></Border.RenderTransform>
          <Border.Effect><DropShadowEffect BlurRadius="60" ShadowDepth="18" Direction="270" Opacity="0.45" Color="#000000"/></Border.Effect>
          <Grid>
            <!-- busy / offline -->
            <StackPanel x:Name="AuthBusyPanel" Visibility="Visible">
              <Image x:Name="AuthLogo0" Width="54" Height="54" HorizontalAlignment="Center"/>
              <TextBlock x:Name="AuthBusyTitle" Text="Checking your account..." FontSize="20" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" Margin="0,18,0,0" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap"/>
              <ProgressBar x:Name="AuthBusyBar" IsIndeterminate="True" Height="4" Margin="20,18,20,0" Foreground="#FF8A1F" Background="#1A2440" BorderThickness="0"/>
              <Border x:Name="AuthBusyErr" Style="{StaticResource AuthErr}">
                <TextBlock x:Name="AuthBusyErrTxt" Text="" Foreground="#F87171" FontSize="13" TextWrapping="Wrap"/>
              </Border>
              <Button x:Name="BtnAuthRetry" Style="{StaticResource PrimaryBtn}" Content="Try again" Padding="18,12" Margin="0,16,0,0" Visibility="Collapsed"/>
              <Button x:Name="BtnAuthBusyOut" Style="{StaticResource LinkBtn}" Content="Sign in with another account" Margin="0,12,0,0" Visibility="Collapsed"/>
            </StackPanel>

            <!-- sign in -->
            <StackPanel x:Name="AuthLoginPanel" Visibility="Collapsed">
              <Image x:Name="AuthLogo1" Width="50" Height="50" HorizontalAlignment="Left"/>
              <TextBlock Text="Welcome back" FontSize="25" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" Margin="0,16,0,0"/>
              <TextBlock x:Name="AuthLoginSub" Text="Sign in to use Silvan Boost." FontSize="14" Foreground="#9AA5BF" Margin="0,4,0,4" TextWrapping="Wrap"/>
              <TextBlock Text="USERNAME" Style="{StaticResource AuthLbl}"/>
              <TextBox x:Name="AuthLUser" Style="{StaticResource AuthField}" MaxLength="20"/>
              <TextBlock Text="PASSWORD" Style="{StaticResource AuthLbl}"/>
              <PasswordBox x:Name="AuthLPass" Style="{StaticResource AuthPass}" MaxLength="100"/>
              <StackPanel Orientation="Horizontal" Margin="0,16,0,0">
                <CheckBox x:Name="AuthRemember" Style="{StaticResource Toggle}" IsChecked="True" VerticalAlignment="Center"/>
                <TextBlock Text="Stay signed in" Foreground="#9AA5BF" FontSize="13" Margin="10,0,0,0" VerticalAlignment="Center"/>
              </StackPanel>
              <Border x:Name="AuthLErr" Style="{StaticResource AuthErr}">
                <TextBlock x:Name="AuthLErrTxt" Text="" Foreground="#F87171" FontSize="13" TextWrapping="Wrap"/>
              </Border>
              <Button x:Name="BtnAuthLogin" Style="{StaticResource PrimaryBtn}" Content="Sign in" Padding="18,12" Margin="0,18,0,0" FontSize="14.5"/>
              <Button x:Name="BtnAuthToReg" Style="{StaticResource LinkBtn}" Content="No account yet? Create account" Margin="0,12,0,0"/>
            </StackPanel>

            <!-- register -->
            <StackPanel x:Name="AuthRegPanel" Visibility="Collapsed">
              <Image x:Name="AuthLogo2" Width="50" Height="50" HorizontalAlignment="Left"/>
              <TextBlock Text="Create account" FontSize="25" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" Margin="0,16,0,0"/>
              <TextBlock Text="Silvan unlocks your account afterwards." FontSize="14" Foreground="#9AA5BF" Margin="0,4,0,4" TextWrapping="Wrap"/>
              <TextBlock Text="USERNAME" Style="{StaticResource AuthLbl}"/>
              <TextBox x:Name="AuthRUser" Style="{StaticResource AuthField}" MaxLength="20"/>
              <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="12"/><ColumnDefinition/></Grid.ColumnDefinitions>
                <StackPanel>
                  <TextBlock Text="PASSWORD" Style="{StaticResource AuthLbl}"/>
                  <PasswordBox x:Name="AuthRPass" Style="{StaticResource AuthPass}" MaxLength="100"/>
                </StackPanel>
                <StackPanel Grid.Column="2">
                  <TextBlock Text="REPEAT" Style="{StaticResource AuthLbl}"/>
                  <PasswordBox x:Name="AuthRPass2" Style="{StaticResource AuthPass}" MaxLength="100"/>
                </StackPanel>
              </Grid>
              <Border CornerRadius="10" Background="#0E1628" BorderBrush="#2A3858" BorderThickness="1" Padding="12,10" Margin="0,16,0,0">
                <DockPanel>
                  <TextBlock Text="YOUR PC-ID" Foreground="#7F8BA6" FontSize="11" FontWeight="Bold" VerticalAlignment="Center"/>
                  <TextBlock x:Name="AuthPcId" Text="" FontFamily="Consolas" FontSize="14.5" FontWeight="SemiBold" HorizontalAlignment="Right" VerticalAlignment="Center"/>
                </DockPanel>
              </Border>
              <Border x:Name="AuthRErr" Style="{StaticResource AuthErr}">
                <TextBlock x:Name="AuthRErrTxt" Text="" Foreground="#F87171" FontSize="13" TextWrapping="Wrap"/>
              </Border>
              <Button x:Name="BtnAuthReg" Style="{StaticResource PrimaryBtn}" Content="Create account" Padding="18,12" Margin="0,18,0,0" FontSize="14.5"/>
              <Button x:Name="BtnAuthToLogin" Style="{StaticResource LinkBtn}" Content="I already have an account" Margin="0,12,0,0"/>
            </StackPanel>

            <!-- waiting for approval -->
            <StackPanel x:Name="AuthWaitPanel" Visibility="Collapsed">
              <Grid Width="76" Height="76" HorizontalAlignment="Center">
                <Ellipse Stroke="#1A2540" StrokeThickness="4"/>
                <Path x:Name="AuthSpin" Stroke="#FF8A1F" StrokeThickness="4" StrokeStartLineCap="Round" StrokeEndLineCap="Round" Data="M 38,2 A 36,36 0 0 1 74,38" RenderTransformOrigin="0.5,0.5">
                  <Path.RenderTransform><RotateTransform Angle="0"/></Path.RenderTransform>
                </Path>
              </Grid>
              <TextBlock x:Name="AuthWaitTitle" Text="Almost there" FontSize="23" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" Margin="0,18,0,0" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap"/>
              <TextBlock Text="Silvan got your request and still has to unlock you." FontSize="14" Foreground="#9AA5BF" Margin="0,6,0,0" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap"/>
              <StackPanel Margin="0,20,0,0">
                <DockPanel Margin="0,0,0,9">
                  <Border Width="24" Height="24" CornerRadius="12" Background="#212ED47A"><TextBlock Text="&#xE73E;" FontFamily="{StaticResource IconFont}" FontSize="11" Foreground="#2ED47A" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
                  <TextBlock Text="Account created" FontSize="14" Margin="11,0,0,0" VerticalAlignment="Center"/>
                </DockPanel>
                <DockPanel Margin="0,0,0,9">
                  <Border Width="24" Height="24" CornerRadius="12" Background="#212ED47A"><TextBlock Text="&#xE73E;" FontFamily="{StaticResource IconFont}" FontSize="11" Foreground="#2ED47A" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
                  <TextBlock Text="Request sent to Silvan" FontSize="14" Margin="11,0,0,0" VerticalAlignment="Center"/>
                </DockPanel>
                <DockPanel>
                  <Border Width="24" Height="24" CornerRadius="12" Background="#24FF8A1F"><TextBlock Text="3" FontSize="12" FontWeight="Bold" Foreground="#FF8A1F" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
                  <TextBlock Text="Waiting for approval..." FontSize="14" Foreground="#9AA5BF" Margin="11,0,0,0" VerticalAlignment="Center"/>
                </DockPanel>
              </StackPanel>
              <TextBlock Text="You can close Silvan Boost and come back later." FontSize="12.5" Foreground="#7F8BA6" Margin="0,18,0,0" HorizontalAlignment="Center" TextWrapping="Wrap" TextAlignment="Center"/>
              <Button x:Name="BtnAuthWaitOut" Style="{StaticResource GhostBtn}" Content="Sign out" Padding="18,11" Margin="0,14,0,0"/>
            </StackPanel>

            <!-- unlocked -->
            <StackPanel x:Name="AuthOkPanel" Visibility="Collapsed">
              <Border x:Name="AuthOkCheck" Width="66" Height="66" CornerRadius="33" Background="#242ED47A" BorderBrush="#802ED47A" BorderThickness="1.5" HorizontalAlignment="Center" RenderTransformOrigin="0.5,0.5">
                <Border.RenderTransform><ScaleTransform ScaleX="1" ScaleY="1"/></Border.RenderTransform>
                <TextBlock Text="&#xE73E;" FontFamily="{StaticResource IconFont}" FontSize="27" Foreground="#2ED47A" HorizontalAlignment="Center" VerticalAlignment="Center"/>
              </Border>
              <TextBlock Text="You're unlocked" FontSize="25" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" Margin="0,18,0,0" HorizontalAlignment="Center"/>
              <TextBlock x:Name="AuthOkSub" Text="" FontSize="14" Foreground="#9AA5BF" Margin="0,6,0,0" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap"/>
              <Border CornerRadius="12" Background="#0E1628" BorderBrush="#2A3858" BorderThickness="1" Padding="14,12" Margin="0,20,0,0">
                <DockPanel>
                  <Border x:Name="AuthOkPill" DockPanel.Dock="Right" CornerRadius="11" Background="#212ED47A" Padding="10,3" VerticalAlignment="Center">
                    <TextBlock x:Name="AuthOkPillTxt" Text="" FontSize="12" FontWeight="Bold" Foreground="#5BE39A"/>
                  </Border>
                  <StackPanel>
                    <TextBlock Text="YOUR PLAN" Foreground="#7F8BA6" FontSize="11" FontWeight="Bold"/>
                    <TextBlock x:Name="AuthOkPlan" Text="" FontSize="16" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" Margin="0,2,0,0"/>
                  </StackPanel>
                </DockPanel>
              </Border>
              <Button x:Name="BtnAuthGo" Style="{StaticResource PrimaryBtn}" Content="Let's go" Padding="18,12" Margin="0,20,0,0" FontSize="14.5"/>
            </StackPanel>

            <!-- plan ended -->
            <StackPanel x:Name="AuthExpPanel" Visibility="Collapsed">
              <Border Width="66" Height="66" CornerRadius="33" Background="#1FFBBF24" BorderBrush="#73FBBF24" BorderThickness="1.5" HorizontalAlignment="Center">
                <TextBlock Text="&#xE823;" FontFamily="{StaticResource IconFont}" FontSize="27" Foreground="#FBBF24" HorizontalAlignment="Center" VerticalAlignment="Center"/>
              </Border>
              <TextBlock Text="Your plan has ended" FontSize="25" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" Margin="0,18,0,0" HorizontalAlignment="Center"/>
              <TextBlock x:Name="AuthExpSub" Text="" FontSize="14" Foreground="#9AA5BF" Margin="0,6,0,0" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap"/>
              <DockPanel Margin="0,20,0,0">
                <Border Width="24" Height="24" CornerRadius="12" Background="#24FF8A1F"><TextBlock Text="&#xE895;" FontFamily="{StaticResource IconFont}" FontSize="11" Foreground="#FF8A1F" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
                <TextBlock Text="Waiting for renewal..." FontSize="14" Foreground="#9AA5BF" Margin="11,0,0,0" VerticalAlignment="Center"/>
              </DockPanel>
              <Button x:Name="BtnAuthExpOut" Style="{StaticResource GhostBtn}" Content="Sign out" Padding="18,11" Margin="0,20,0,0"/>
            </StackPanel>

            <!-- locked -->
            <StackPanel x:Name="AuthLockPanel" Visibility="Collapsed">
              <Border Width="66" Height="66" CornerRadius="33" Background="#1FF87171" BorderBrush="#73F87171" BorderThickness="1.5" HorizontalAlignment="Center">
                <TextBlock Text="&#xE72E;" FontFamily="{StaticResource IconFont}" FontSize="26" Foreground="#F87171" HorizontalAlignment="Center" VerticalAlignment="Center"/>
              </Border>
              <TextBlock x:Name="AuthLockTitle" Text="This account is locked" FontSize="24" FontWeight="SemiBold" FontFamily="Segoe UI Variable Display, Segoe UI" Margin="0,18,0,0" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap"/>
              <TextBlock x:Name="AuthLockSub" Text="" FontSize="14" Foreground="#9AA5BF" Margin="0,6,0,0" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap"/>
              <Border x:Name="AuthLockErr" Style="{StaticResource AuthErr}">
                <TextBlock x:Name="AuthLockErrTxt" Text="" Foreground="#F87171" FontSize="13" TextWrapping="Wrap"/>
              </Border>
              <Button x:Name="BtnAuthLockOut" Style="{StaticResource GhostBtn}" Content="Sign in with another account" Padding="18,11" Margin="0,20,0,0"/>
            </StackPanel>
          </Grid>
        </Border>
      </Grid>

    </Grid>
  </Border>
</Window>
'@


# ------------------------------------------------------------------ App Cleaner catalogue
function A($P, $N, $D, [bool]$Rec, $Kind = 'Microsoft') { @{ P = $P; N = $N; D = $D; Rec = $Rec; Kind = $Kind; Hits = @(); Toggle = $null } }
$script:AppCatalog = @(
    (A 'Microsoft.BingNews' 'Microsoft News' 'News feed app with ads.' $true),
    (A 'Microsoft.BingWeather' 'Weather' 'MSN Weather app.' $true),
    (A 'Microsoft.BingSearch' 'Bing Search' 'Bing web search integration.' $true),
    (A 'Microsoft.GetHelp' 'Get Help' 'Microsoft support chat app.' $true),
    (A 'Microsoft.Getstarted' 'Tips' 'Windows tips and tutorials.' $true),
    (A 'Microsoft.MicrosoftSolitaireCollection' 'Solitaire Collection' 'Card games with ads and subscriptions.' $true),
    (A 'Microsoft.People' 'People' 'Old contacts app.' $true),
    (A 'Microsoft.WindowsFeedbackHub' 'Feedback Hub' 'Sends feedback to Microsoft.' $true),
    (A 'Microsoft.WindowsMaps' 'Maps' 'Offline maps app.' $true),
    (A 'Microsoft.MicrosoftOfficeHub' 'Microsoft 365 (Office) hub' 'Launcher that advertises Microsoft 365. Office itself is not removed.' $true),
    (A 'Microsoft.PowerAutomateDesktop' 'Power Automate' 'Business automation tool.' $true),
    (A 'Microsoft.Windows.DevHome' 'Dev Home' 'Developer dashboard.' $true),
    (A 'Microsoft.549981C3F5F10' 'Cortana' 'Discontinued voice assistant.' $true),
    (A 'Microsoft.Copilot' 'Copilot app' 'Microsoft AI assistant app.' $true),
    (A 'Clipchamp.Clipchamp' 'Clipchamp' 'Video editor that pushes a subscription.' $true),
    (A 'MicrosoftTeams' 'Teams (personal)' 'Consumer Teams chat app that starts with Windows.' $true),
    (A 'MSTeams' 'Teams (new)' 'Microsoft Teams. Keep it if you need it for school or work.' $false),
    (A 'Microsoft.MixedReality.Portal' 'Mixed Reality Portal' 'Only needed for Windows VR headsets.' $true),
    (A 'Microsoft.Microsoft3DViewer' '3D Viewer' 'Viewer for 3D models.' $true),
    (A 'Microsoft.SkypeApp' 'Skype' 'Skype was shut down by Microsoft.' $true),
    (A 'Microsoft.Todos' 'Microsoft To Do' 'Task list app.' $false),
    (A 'Microsoft.OutlookForWindows' 'Outlook (new)' 'New Outlook mail app.' $false),
    (A 'Microsoft.ZuneVideo' 'Films & TV' 'Video player and store.' $false),
    (A 'Microsoft.ZuneMusic' 'Media Player' 'Music and video player.' $false),
    (A 'Microsoft.MicrosoftStickyNotes' 'Sticky Notes' 'Desktop notes.' $false),
    (A 'Microsoft.WindowsAlarms' 'Clock' 'Alarms, timer and focus sessions.' $false),
    (A 'Microsoft.WindowsSoundRecorder' 'Sound Recorder' 'Simple audio recorder.' $false),
    (A 'Microsoft.YourPhone' 'Phone Link' 'Connects your phone. Keep it if you use it.' $false),
    (A 'Microsoft.Office.OneNote' 'OneNote (Store)' 'Note-taking app.' $false),
    (A 'MicrosoftCorporationII.QuickAssist' 'Quick Assist' 'Remote help tool.' $false),
    (A 'Microsoft.GamingApp' 'Xbox app' 'Needed for PC Game Pass. Remove only if you do not use it.' $false 'Xbox'),
    (A 'Microsoft.XboxGamingOverlay' 'Xbox Game Bar' 'Win+G overlay. Needed for Xbox party chat and some capture features.' $false 'Xbox'),
    (A '*CandyCrush*' 'Candy Crush' 'Preinstalled promo game.' $true 'Third-party'),
    (A '*BubbleWitch*' 'Bubble Witch' 'Preinstalled promo game.' $true 'Third-party'),
    (A '*MarchofEmpires*' 'March of Empires' 'Preinstalled promo game.' $true 'Third-party'),
    (A '*Disney*' 'Disney+' 'Preinstalled promo app.' $true 'Third-party'),
    (A '*TikTok*' 'TikTok' 'Preinstalled promo app.' $true 'Third-party'),
    (A '*Facebook*' 'Facebook' 'Preinstalled promo app.' $true 'Third-party'),
    (A '*Instagram*' 'Instagram' 'Preinstalled promo app.' $true 'Third-party'),
    (A '*LinkedIn*' 'LinkedIn' 'Preinstalled promo app.' $true 'Third-party'),
    (A '*Netflix*' 'Netflix' 'Streaming app. Keep it if you use it.' $false 'Third-party'),
    (A '*AmazonPrimeVideo*' 'Prime Video' 'Streaming app. Keep it if you use it.' $false 'Third-party'),
    (A '*SpotifyMusic*' 'Spotify' 'Music app. Keep it if you use it.' $false 'Third-party'),
    (A '__onedrive' 'OneDrive' 'Cloud sync client. Your files stay in your OneDrive folder and online.' $false)
)
$script:AppsLoaded = $false

function Find-OneDriveSetup {
    $c = @("$env:SystemRoot\System32\OneDriveSetup.exe", "$env:SystemRoot\SysWOW64\OneDriveSetup.exe")
    $c += @(Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\OneDrive\*\OneDriveSetup.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $c += @(Get-ChildItem -Path "$env:ProgramFiles\Microsoft OneDrive\*\OneDriveSetup.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $c | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}
function Test-OneDrive {
    (Test-Path "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe") -or (Test-Path "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe")
}

function New-AppRow($a) {
    $kindCol = '#A9B3CC'
    $chip = ''
    if ($a.Rec) { $chip = '<Border CornerRadius="6" Padding="7,1" Margin="8,0,0,0" Background="#1A2ED47A" VerticalAlignment="Center"><TextBlock Text="Recommended" FontSize="10.5" Foreground="#5BE39A"/></Border>' }
    elseif ($a.Kind -eq 'Xbox') { $chip = '<Border CornerRadius="6" Padding="7,1" Margin="8,0,0,0" Background="#1AF59E0B" VerticalAlignment="Center"><TextBlock Text="Careful" FontSize="10.5" Foreground="#FBBF24"/></Border>' }
    else { $chip = '<Border CornerRadius="6" Padding="7,1" Margin="8,0,0,0" Background="#1A2440" VerticalAlignment="Center"><TextBlock Text="Optional" FontSize="10.5" Foreground="#A9B3CC"/></Border>' }
    $ini = ($a.N -replace '[^A-Za-z0-9 ]', '').Trim()
    $parts = @($ini -split '\s+' | Where-Object { $_ })
    if ($parts.Count -ge 2) { $ini = ($parts[0].Substring(0, 1) + $parts[1].Substring(0, 1)).ToUpper() } else { $ini = $ini.Substring(0, [Math]::Min(2, $ini.Length)).ToUpper() }
    $xml = @"
<Border $NS Style="{DynamicResource Card}" Padding="14,12" Margin="0,0,12,10">
  <DockPanel>
    <CheckBox x:Name="Tg" DockPanel.Dock="Right" Style="{DynamicResource Toggle}" VerticalAlignment="Center"/>
    <Border DockPanel.Dock="Left" Width="40" Height="40" CornerRadius="10" Background="#1A2440">
      <TextBlock Text="$(X $ini)" FontSize="13" FontWeight="Bold" Foreground="#FF9A3C" HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
    <StackPanel Margin="12,0,12,0" VerticalAlignment="Center">
      <StackPanel Orientation="Horizontal">
        <TextBlock Text="$(X $a.N)" FontSize="14" FontWeight="SemiBold"/>
        $chip
      </StackPanel>
      <TextBlock Text="$(X $a.D)" FontSize="12" Foreground="$kindCol" Margin="0,3,0,0" TextTrimming="CharacterEllipsis"/>
    </StackPanel>
  </DockPanel>
</Border>
"@
    $row = [System.Windows.Markup.XamlReader]::Parse($xml)
    $row.ToolTip = "$($a.N) - $($a.D)"
    $tg = $row.FindName('Tg')
    $tg.Add_Click({ Update-AppsCount })
    $a.Toggle = $tg
    $row
}

function Load-Apps {
    Show-Overlay 'Looking for removable apps...'
    try {
        $pk = @(Get-AppxPackage -ErrorAction SilentlyContinue)
        $AppList.Children.Clear()
        $n = 0
        foreach ($a in $AppCatalog) {
            if ($a.P -eq '__onedrive') { $a.Hits = @(); if (Test-OneDrive) { $a.Hits = @('onedrive') } }
            else { $a.Hits = @($pk | Where-Object { $_.Name -like $a.P } | ForEach-Object { $_.PackageFullName } | Select-Object -Unique) }
            $a.Toggle = $null
            if ($a.Hits.Count -gt 0) { [void]$AppList.Children.Add((New-AppRow $a)); $n++ }
        }
        $AppsSub.Text = "$n removable apps found on this PC. Pick exactly which ones you want gone."
        if ($n -eq 0) { $AppsSub.Text = 'No unnecessary apps found - this PC is already clean.' }
        $script:AppsLoaded = $true
        Update-AppsCount
    } catch { Write-Log "App scan error: $_" }
    Hide-Overlay
}

function Update-AppsCount {
    $n = @($AppCatalog | Where-Object { $_.Toggle -and $_.Toggle.IsChecked }).Count
    $BtnAppsRemove.Content = "Remove selected ($n)"
    $BtnAppsRemove.IsEnabled = ($n -gt 0)
}

function Select-Apps([string]$mode) {
    foreach ($a in $AppCatalog) {
        if ($a.Toggle) { $a.Toggle.IsChecked = ($mode -eq 'rec' -and $a.Rec) }
    }
    Update-AppsCount
}

function Remove-SelectedApps {
    $sel = @($AppCatalog | Where-Object { $_.Toggle -and $_.Toggle.IsChecked })
    if ($sel.Count -eq 0) { return }
    $names = ($sel | ForEach-Object { ' - ' + $_.N }) -join "`n"
    $r = Show-Msg "Remove these $($sel.Count) apps?`n`n$names`n`nYou can reinstall them later from the Microsoft Store." 'App Cleaner' 'YesNo' 'Question'
    if ([string]$r -ne 'Yes') { return }
    $ok = 0; $fail = New-Object System.Collections.ArrayList; $i = 0
    foreach ($a in $sel) {
        $i++
        Show-Overlay ("Removing {0} of {1}`n{2}" -f $i, $sel.Count, $a.N)
        try {
            if ($a.P -eq '__onedrive') {
                $setup = Find-OneDriveSetup
                if (-not $setup) { throw 'OneDrive uninstaller not found.' }
                Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
                $p = Start-Process -FilePath $setup -ArgumentList '/uninstall' -PassThru -WindowStyle Hidden
                $p.WaitForExit(120000) | Out-Null
            } else {
                foreach ($full in $a.Hits) { Remove-AppxPackage -Package $full -ErrorAction Stop }
            }
            $ok++; Write-Log "Removed app: $($a.N)"
        } catch {
            [void]$fail.Add($a.N); Write-Log "FAILED to remove $($a.N): $($_.Exception.Message)"
        }
    }
    Hide-Overlay
    $msg = "$ok app(s) removed."
    if ($fail.Count -gt 0) { $msg += "`n`nCould not remove:`n - " + ($fail -join "`n - ") }
    Set-Status "App Cleaner: $ok app(s) removed"
    Show-Msg $msg 'App Cleaner' | Out-Null
    Load-Apps
}

# ------------------------------------------------------------------ Game presets
$script:PresetComp = @('ultimate-plan', 'power-throttling', 'hags', 'game-mode', 'game-dvr', 'mmcss-games', 'sys-responsiveness',
    'win32prio', 'core-parking', 'timer-res', 'usb-suspend', 'pcie-aspm', 'mouse-accel', 'sticky-keys',
    'net-throttle', 'nic-power', 'delivery-opt', 'sysmain', 'bg-apps', 'fast-startup')
$script:PresetCasual = @('ultimate-plan', 'power-throttling', 'hags', 'game-mode', 'game-dvr', 'mmcss-games', 'sys-responsiveness',
    'win32prio', 'pcie-aspm', 'sticky-keys', 'sysmain', 'bg-apps', 'fast-startup')

$script:GPUPREF = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'
$script:LAYERS  = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
$script:IFEO    = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'

function G {
    param($Id, $Name, $Short, $Genre, $Type, $Exes = @(), $Steam = @(), $Match = $null, $Paths = @(), [bool]$Fso = $false, [bool]$Prio = $true, $C1, $C2, $Tips)
    @{ Id = $Id; Name = $Name; Short = $Short; Genre = $Genre; Type = $Type; Exes = @($Exes); Steam = @($Steam); Match = $Match
       Paths = @($Paths); Fso = $Fso; Prio = $Prio; C1 = $C1; C2 = $C2; Tips = $Tips; Found = @(); Installed = $false; Custom = $false; UI = $null }
}
$script:GameCatalog = @(
    (G -Id 'fortnite' -Name 'Fortnite' -Short 'FN' -Genre 'Battle royale' -Type 'comp' -Exes 'FortniteClient-Win64-Shipping.exe' -Match '^Fortnite' `
       -Paths @("$env:ProgramFiles\Epic Games\Fortnite") -C1 '#7C3AED' -C2 '#2563EB' `
       -Tips "Rendering mode: Performance for maximum FPS, DirectX 12 if your GPU is strong.`nNVIDIA Reflex: On + Boost.`nShadows, Global Illumination, Reflections: Off.`nView distance: Far or Epic (helps spot players).`nFrame rate limit: your monitor's refresh rate or higher."),
    (G -Id 'valorant' -Name 'VALORANT' -Short 'VAL' -Genre 'Tactical shooter' -Type 'comp' -Exes 'VALORANT-Win64-Shipping.exe' -Match 'VALORANT' `
       -Paths @('C:\Riot Games\VALORANT') -Fso $true -C1 '#E11D48' -C2 '#7F1D1D' `
       -Tips "NVIDIA Reflex: On + Boost.`nMaterial, Texture, Detail quality: Low or Medium.`nVignette, Bloom, Distortion, Shadows: Off.`nAnti-aliasing: MSAA 2x or None.`nMultithreaded rendering: On.`nLimit FPS: Off (or well above your refresh rate)."),
    (G -Id 'cs2' -Name 'Counter-Strike 2' -Short 'CS2' -Genre 'Tactical shooter' -Type 'comp' -Exes 'cs2.exe' -Steam 'Counter-Strike Global Offensive' `
       -Fso $true -C1 '#F59E0B' -C2 '#78350F' `
       -Tips "Boost player contrast: Enabled.`nNVIDIA Reflex: Enabled + Boost.`nShader detail and particle detail: Low.`nMultisampling: 2x or 4x MSAA.`nDisplay mode: Fullscreen.`nMax FPS in game: 0 (unlimited) or a cap you can hold steadily."),
    (G -Id 'lol' -Name 'League of Legends' -Short 'LoL' -Genre 'MOBA' -Type 'comp' -Exes 'League of Legends.exe' -Match 'League of Legends' `
       -Paths @('C:\Riot Games\League of Legends') -Fso $true -C1 '#0EA5E9' -C2 '#1E3A8A' `
       -Tips "Window mode: Full screen.`nFrame rate cap: Uncapped or at least your refresh rate.`nWait for vertical sync: Off.`nAnti-aliasing: Off.`nCharacter inking: Off."),
    (G -Id 'apex' -Name 'Apex Legends' -Short 'APEX' -Genre 'Battle royale' -Type 'comp' -Exes @('r5apex.exe', 'r5apex_dx12.exe') -Steam 'Apex Legends' -Match 'Apex Legends' `
       -Fso $true -C1 '#DC2626' -C2 '#450A0A' `
       -Tips "NVIDIA Reflex: Enabled + Boost.`nAdaptive resolution FPS target: 0.`nTexture streaming budget: match your VRAM.`nAmbient occlusion, volumetric lighting, dynamic spot shadows: Off.`nModel detail: Low or Medium."),
    (G -Id 'cod' -Name 'Call of Duty' -Short 'COD' -Genre 'Shooter' -Type 'comp' -Exes @('cod.exe', 'cod24-cod.exe', 'cod25-cod.exe') -Steam @('Call of Duty HQ', 'Call of Duty') -Match 'Call of Duty' `
       -Prio $false -C1 '#4B5563' -C2 '#111827' `
       -Tips "NVIDIA Reflex: On + Boost.`nUpscaling: DLSS / FSR Quality or Balanced.`nVRAM scale target: around 80%.`nShadow quality and screen-space reflections: Low.`nOn-demand texture streaming: Off if your internet is slow."),
    (G -Id 'rocket' -Name 'Rocket League' -Short 'RL' -Genre 'Sports' -Type 'comp' -Exes 'RocketLeague.exe' -Steam 'rocketleague' -Match 'Rocket League' `
       -Paths @("$env:ProgramFiles\Epic Games\rocketleague") -Fso $true -C1 '#2563EB' -C2 '#F97316' `
       -Tips "Display mode: Fullscreen, Vertical sync: Off.`nFrame rate: Uncapped or above your refresh rate.`nRender quality: High Performance.`nWeather effects, dynamic shadows, motion blur: Off.`nWorld detail: Performance."),
    (G -Id 'minecraft' -Name 'Minecraft (Java)' -Short 'MC' -Genre 'Sandbox' -Type 'casual' -Paths @("$env:APPDATA\.minecraft") -Prio $false -C1 '#16A34A' -C2 '#14532D' `
       -Tips "Install Sodium (with Fabric) - often doubles or triples FPS.`nRender distance: 12-16 chunks.`nAllocated RAM in the launcher: 4-6 GB (never more than half of your RAM).`nVSync: Off, Max framerate: Unlimited.`nGraphics: Fast, clouds: Off."),
    (G -Id 'roblox' -Name 'Roblox' -Short 'RBX' -Genre 'Platform' -Type 'casual' -Exes 'RobloxPlayerBeta.exe' -Paths @("$env:LOCALAPPDATA\Roblox\Versions") `
       -C1 '#334155' -C2 '#0F172A' `
       -Tips "Roblox caps FPS at 60 by default - in Roblox Settings set Maximum Frame Rate to your monitor's refresh rate.`nGraphics mode: Manual, lower the slider in very busy games.`nClose browser tabs while playing - Roblox is often CPU-limited."),
    (G -Id 'gta5' -Name 'GTA V' -Short 'GTA' -Genre 'Open world' -Type 'casual' -Exes @('GTA5.exe', 'GTA5_Enhanced.exe') -Steam @('Grand Theft Auto V', 'Grand Theft Auto V Enhanced') -Match 'Grand Theft Auto V' `
       -C1 '#16A34A' -C2 '#1E293B' `
       -Tips "Grass quality: High, not Ultra (Ultra costs a lot of FPS).`nMSAA: Off - use FXAA, or DLSS in the Enhanced edition.`nReflection MSAA: Off.`nExtended distance scaling: low to medium."),
    (G -Id 'ow2' -Name 'Overwatch 2' -Short 'OW2' -Genre 'Hero shooter' -Type 'comp' -Exes 'Overwatch.exe' -Steam 'Overwatch' -Match 'Overwatch' `
       -C1 '#F97316' -C2 '#334155' `
       -Tips "NVIDIA Reflex: Enabled + Boost.`nRender scale: 100%.`nFrame rate: Custom, set to your refresh rate or higher.`nDynamic reflections, local fog detail, shadow detail: Low or Off."),
    (G -Id 'r6' -Name 'Rainbow Six Siege' -Short 'R6' -Genre 'Tactical shooter' -Type 'comp' -Exes @('RainbowSix.exe', 'RainbowSix_Vulkan.exe', 'RainbowSixGame.exe') -Steam "Tom Clancy's Rainbow Six Siege" -Match 'Rainbow Six' `
       -Fso $true -C1 '#0369A1' -C2 '#0C0A09' `
       -Tips "The Vulkan version usually gives higher FPS.`nNVIDIA Reflex: On + Boost.`nRender scaling: 100.`nLens effects and zoom-in depth of field: Off."),
    (G -Id 'pubg' -Name 'PUBG: Battlegrounds' -Short 'PUBG' -Genre 'Battle royale' -Type 'comp' -Exes 'TslGame.exe' -Steam 'PUBG' -Match 'PUBG' `
       -Fso $true -C1 '#CA8A04' -C2 '#422006' `
       -Tips "Anti-aliasing: Ultra (helps visibility, little FPS cost).`nPost-processing, shadows, foliage, effects: Very Low.`nView distance: Medium or higher.`nTextures: as high as your VRAM allows."),
    (G -Id 'rust' -Name 'Rust' -Short 'RUST' -Genre 'Survival' -Type 'comp' -Exes 'RustClient.exe' -Steam 'Rust' `
       -Fso $true -C1 '#B45309' -C2 '#292524' `
       -Tips "Shadow quality: 1, water quality: 0.`nGrass displacement: Off.`nMax gibs: 0.`nGraphics quality: lower it on busy servers - Rust is CPU-heavy."),
    (G -Id 'rivals' -Name 'Marvel Rivals' -Short 'MR' -Genre 'Hero shooter' -Type 'comp' -Exes 'Marvel-Win64-Shipping.exe' -Steam 'MarvelRivals' -Match 'Marvel Rivals' `
       -C1 '#B91C1C' -C2 '#1E1B4B' `
       -Tips "NVIDIA Reflex: On + Boost.`nUpscaling: DLSS / FSR Quality.`nGlobal illumination and reflections: Low.`nFrame generation: Off for competitive play (adds latency)."),
    (G -Id 'eafc' -Name 'EA SPORTS FC' -Short 'FC' -Genre 'Football' -Type 'casual' -Exes @('FC25.exe', 'FC26.exe') -Steam @('EA SPORTS FC 25', 'EA SPORTS FC 26') -Match 'EA SPORTS FC' `
       -C1 '#059669' -C2 '#064E3B' `
       -Tips "Display mode: Fullscreen.`nFrame rate: 60 is the game's simulation rate - higher mainly smooths menus.`nVSync: Off with G-Sync / FreeSync, else On.`nRendering quality: High is enough."),
    (G -Id 'cyberpunk' -Name 'Cyberpunk 2077' -Short 'CP77' -Genre 'RPG' -Type 'casual' -Exes 'Cyberpunk2077.exe' -Steam 'Cyberpunk 2077' -Match 'Cyberpunk 2077' `
       -C1 '#EAB308' -C2 '#0E7490' `
       -Tips "DLSS: Quality or Balanced.`nRay tracing: Off, or Medium together with DLSS on RTX cards.`nScreen space reflections: Medium (Psycho costs a lot).`nCrowd density: Medium (CPU heavy).")
)
$script:Games = @()
$script:GamesLoaded = $false

function Get-SteamLibraries {
    $libs = New-Object System.Collections.ArrayList
    $root = Get-RegValue 'HKCU:\Software\Valve\Steam' 'SteamPath'
    if (-not $root) { $root = Get-RegValue 'HKLM:\SOFTWARE\WOW6432Node\Valve\Steam' 'InstallPath' }
    if ($root) {
        $root = $root -replace '/', '\'
        [void]$libs.Add($root)
        $vdf = Join-Path $root 'steamapps\libraryfolders.vdf'
        if (Test-Path -LiteralPath $vdf) {
            foreach ($m in [regex]::Matches((Get-Content -LiteralPath $vdf -Raw), '"path"\s+"([^"]+)"')) {
                [void]$libs.Add(($m.Groups[1].Value -replace '\\\\', '\'))
            }
        }
    }
    @($libs | ForEach-Object { $_.TrimEnd('\') } | Sort-Object -Unique)
}

function Get-InstallIndex {
    $idx = New-Object System.Collections.ArrayList
    $man = Join-Path $env:ProgramData 'Epic\EpicGamesLauncher\Data\Manifests'
    if (Test-Path -LiteralPath $man) {
        foreach ($f in Get-ChildItem -LiteralPath $man -Filter '*.item' -ErrorAction SilentlyContinue) {
            try { $j = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json; [void]$idx.Add(@{ Name = [string]$j.DisplayName; Path = [string]$j.InstallLocation }) } catch { }
        }
    }
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        foreach ($e in @(Get-ItemProperty -Path $k -ErrorAction SilentlyContinue)) {
            if ($e.DisplayName -and $e.InstallLocation) { [void]$idx.Add(@{ Name = [string]$e.DisplayName; Path = ([string]$e.InstallLocation).Trim('"') }) }
        }
    }
    $idx
}

function Find-GameExes($g, $steamLibs, $index) {
    $roots = New-Object System.Collections.ArrayList
    foreach ($sf in $g.Steam) { if ($sf) { foreach ($lib in $steamLibs) { [void]$roots.Add((Join-Path $lib "steamapps\common\$sf")) } } }
    if ($g.Match) { foreach ($e in $index) { if ($e.Name -match $g.Match -and $e.Path) { [void]$roots.Add($e.Path) } } }
    foreach ($p in $g.Paths) { if ($p) { [void]$roots.Add($p) } }
    $roots = @($roots | Where-Object { $_ -and $_.Length -gt 3 -and (Test-Path -LiteralPath $_) } | ForEach-Object { $_.TrimEnd('\') } | Sort-Object -Unique)
    $found = New-Object System.Collections.ArrayList
    foreach ($r in $roots) {
        foreach ($exe in $g.Exes) {
            if (-not $exe) { continue }
            $hit = Get-ChildItem -LiteralPath $r -Filter $exe -Recurse -Depth 6 -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($hit) { [void]$found.Add($hit.FullName) }
        }
    }
    $g.Found = @($found | Sort-Object -Unique)
    $g.Installed = ($g.Found.Count -gt 0) -or ($g.Exes.Count -eq 0 -and $roots.Count -gt 0)
}

function Get-CustomGames {
    $list = @()
    foreach ($c in @($State.misc['CustomGames'])) {
        if (-not $c -or -not $c.Exe) { continue }
        $short = ([IO.Path]::GetFileNameWithoutExtension([string]$c.Exe) -replace '[^A-Za-z0-9]', '')
        if ($short.Length -gt 4) { $short = $short.Substring(0, 4) }
        $g = G -Id $c.Id -Name $c.Name -Short $short.ToUpper() -Genre 'Custom game' -Type $c.Type -Exes @([IO.Path]::GetFileName([string]$c.Exe)) `
            -C1 '#FF8A1F' -C2 '#1E293B' -Tips "Use the in-game options: turn on NVIDIA Reflex or AMD Anti-Lag if available, disable motion blur and VSync (when you have G-Sync / FreeSync), and set the frame cap to your monitor's refresh rate or higher."
        $g.Custom = $true
        $g.Found = @(); if (Test-Path -LiteralPath $c.Exe) { $g.Found = @([string]$c.Exe) }
        $g.Installed = ($g.Found.Count -gt 0)
        $list += $g
    }
    $list
}

# ---- game artwork: Steam cache on this PC, official Steam image server, or the game's own splash image
$script:SteamAppIds = @{ cs2 = 730; apex = 1172470; rust = 252490; pubg = 578080; gta5 = 271590; r6 = 359550; rocket = 252950
    ow2 = 2357570; rivals = 2767030; cod = 1938090; cyberpunk = 1091500; eafc = 2669320 }
$script:ArtDir = Join-Path $DataDir 'art'

function Get-ImageWidth([string]$path) {
    $fs = $null
    try {
        $fs = [IO.File]::OpenRead($path)
        $dec = [System.Windows.Media.Imaging.BitmapDecoder]::Create($fs, [System.Windows.Media.Imaging.BitmapCreateOptions]::DelayCreation, [System.Windows.Media.Imaging.BitmapCacheOption]::None)
        return [int]$dec.Frames[0].PixelWidth
    } catch { return 0 } finally { if ($fs) { $fs.Close() } }
}

function Test-GoodArt([string]$path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return $false }
    if ((Split-Path -Leaf $path) -match 'blur|logo|icon|capsule_231|small') { return $false }
    (Get-ImageWidth $path) -ge 600
}

function Find-GameArt($g) {
    $cache = Join-Path $ArtDir "$($g.Id).jpg"
    if (Test-GoodArt $cache) { return $cache }
    $app = $SteamAppIds[$g.Id]
    if ($app) {
        $root = Get-RegValue 'HKCU:\Software\Valve\Steam' 'SteamPath'
        if ($root) {
            $lc = Join-Path ($root -replace '/', '\') 'appcache\librarycache'
            # best first: wide high-res hero art, then the store header
            foreach ($f in @("${app}_library_hero.jpg", "${app}_header.jpg")) { $pp = Join-Path $lc $f; if (Test-GoodArt $pp) { return $pp } }
            $d = Join-Path $lc "$app"
            if (Test-Path -LiteralPath $d) {
                $all = @(Get-ChildItem -LiteralPath $d -Recurse -File -ErrorAction SilentlyContinue)
                foreach ($want in @('library_hero.jpg', 'header.jpg', 'library_header.jpg')) {
                    foreach ($f in @($all | Where-Object { $_.Name -ieq $want } | Sort-Object Length -Descending)) {
                        if (Test-GoodArt $f.FullName) { return $f.FullName }
                    }
                }
            }
        }
    }
    foreach ($exe in @($g.Found)) {
        $dir = Split-Path -Parent $exe
        for ($i = 0; $i -lt 5 -and $dir; $i++) {
            $sp = Join-Path $dir 'Content\Splash\Splash.bmp'
            if (Test-Path -LiteralPath $sp) { return $sp }
            $dir = Split-Path -Parent $dir
        }
    }
    $null
}

function Set-GameArt($g) {
    if (-not $g.UI -or $g.ArtSet) { return }
    $path = Find-GameArt $g
    if (-not $path) { return }
    try {
        $bmp = New-Object System.Windows.Media.Imaging.BitmapImage
        $bmp.BeginInit()
        $bmp.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $bmp.CreateOptions = [System.Windows.Media.Imaging.BitmapCreateOptions]::IgnoreImageCache
        $bmp.DecodePixelWidth = 1000
        $bmp.UriSource = New-Object System.Uri($path)
        $bmp.EndInit()
        $bmp.Freeze()
        $brush = New-Object System.Windows.Media.ImageBrush($bmp)
        $brush.Stretch = 'UniformToFill'
        $brush.AlignmentY = 'Center'
        $brush.RelativeTransform = New-Object System.Windows.Media.ScaleTransform(1, 1, 0.5, 0.5)
        $g.UI.FindName('Banner').Background = $brush
        $g.UI.FindName('ShortTxt').Visibility = 'Collapsed'
        $g.ArtSet = $true
    } catch { Write-Log "Game art for $($g.Name) could not be loaded: $($_.Exception.Message)" }
}

function Start-GameArtDownload {
    $need = @($Games | Where-Object { -not $_.ArtSet -and $SteamAppIds.ContainsKey($_.Id) -and -not (Find-GameArt $_) } | ForEach-Object { @{ Id = $_.Id; App = $SteamAppIds[$_.Id] } })
    if ($need.Count -eq 0 -or $Sync.ArtBusy) { return }
    New-Item -ItemType Directory -Path $ArtDir -Force | Out-Null
    $Sync.ArtBusy = $true
    $rs = [runspacefactory]::CreateRunspace(); $rs.Open()
    $rs.SessionStateProxy.SetVariable('Sync', $Sync)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        param($need, $dir)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        foreach ($n in $need) {
            foreach ($u in @("https://shared.akamai.steamstatic.com/store_item_assets/steam/apps/$($n.App)/library_hero.jpg",
                    "https://cdn.cloudflare.steamstatic.com/steam/apps/$($n.App)/library_hero.jpg",
                    "https://shared.akamai.steamstatic.com/store_item_assets/steam/apps/$($n.App)/header.jpg",
                    "https://cdn.cloudflare.steamstatic.com/steam/apps/$($n.App)/header.jpg")) {
                try {
                    $req = [Net.HttpWebRequest]::Create($u); $req.Timeout = 8000; $req.UserAgent = 'SilvanBoost'
                    $resp = $req.GetResponse(); $ms = New-Object System.IO.MemoryStream
                    $resp.GetResponseStream().CopyTo($ms); $resp.Close()
                    $b = $ms.ToArray()
                    if ($b.Length -gt 20000 -and $b.Length -lt 8MB -and $b[0] -eq 0xFF -and $b[1] -eq 0xD8) {
                        [IO.File]::WriteAllBytes((Join-Path $dir "$($n.Id).jpg"), $b)
                        break
                    }
                } catch { }
            }
        }
        $Sync.ArtBusy = $false
        $Sync.ArtDone = $true
    }).AddArgument($need).AddArgument($ArtDir)
    $script:ArtPs = $ps
    [void]$ps.BeginInvoke()
}

function New-GameCard($g) {
    $dot = [string][char]0x00B7
    $typeTxt = 'Competitive preset'; if ($g.Type -ne 'comp') { $typeTxt = 'Smooth & quality preset' }
    $undoTxt = 'Undo'; if ($g.Custom) { $undoTxt = 'Remove' }
    $xml = @"
<Border $NS Style="{DynamicResource Card}" Padding="0" Margin="0,0,14,14">
  <StackPanel>
    <Grid Height="136">
      <Border x:Name="Banner" CornerRadius="13,13,0,0">
        <Border.Background>
          <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
            <GradientStop Color="$($g.C1)" Offset="0"/>
            <GradientStop Color="$($g.C2)" Offset="1"/>
          </LinearGradientBrush>
        </Border.Background>
      </Border>
      <TextBlock x:Name="ShortTxt" Text="$(X $g.Short)" FontFamily="Segoe UI Variable Display, Segoe UI" FontSize="46" FontWeight="Black" Foreground="#40FFFFFF" HorizontalAlignment="Right" VerticalAlignment="Top" Margin="0,6,16,0"/>
      <Border CornerRadius="13,13,0,0" IsHitTestVisible="False">
        <Border.Background>
          <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
            <GradientStop Color="#00111A2E" Offset="0.2"/>
            <GradientStop Color="#99111A2E" Offset="0.62"/>
            <GradientStop Color="#F7111A2E" Offset="1"/>
          </LinearGradientBrush>
        </Border.Background>
      </Border>
      <Border x:Name="Badge" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="12" CornerRadius="10" Padding="8,3" Background="#B30A0F1C">
        <StackPanel Orientation="Horizontal">
          <Ellipse x:Name="BadgeDot" Width="6" Height="6" Fill="#2ED47A" VerticalAlignment="Center" Margin="0,0,6,0"/>
          <TextBlock x:Name="BadgeTxt" Text="" FontSize="11" FontWeight="SemiBold" Foreground="#FFFFFF"/>
        </StackPanel>
      </Border>
      <StackPanel VerticalAlignment="Bottom" Margin="16,0,16,12" IsHitTestVisible="False">
        <TextBlock Text="$(X $g.Name)" FontSize="18" FontWeight="SemiBold" Foreground="#FFFFFF" TextTrimming="CharacterEllipsis" FontFamily="Segoe UI Variable Display, Segoe UI"/>
        <TextBlock Text="$(X $g.Genre)  $dot  $typeTxt" FontSize="12" Foreground="#C9D1E3" Margin="0,1,0,0" TextTrimming="CharacterEllipsis"/>
      </StackPanel>
    </Grid>
    <StackPanel Margin="16,10,16,14">
      <TextBlock x:Name="Info" Text="" FontSize="11.5" Foreground="#7F8BA6" TextTrimming="CharacterEllipsis"/>
      <DockPanel Margin="0,12,0,0">
        <Button x:Name="Tips" DockPanel.Dock="Right" Style="{DynamicResource GhostBtn}" Padding="12,6" FontSize="12" Content="Pro settings"/>
        <Button x:Name="Undo" DockPanel.Dock="Right" Style="{DynamicResource GhostBtn}" Padding="12,6" FontSize="12" Margin="0,0,8,0" Content="$undoTxt"/>
        <Button x:Name="Go" Style="{DynamicResource PrimaryBtn}" Padding="16,6" FontSize="12" HorizontalAlignment="Left" Content="Optimize"/>
      </DockPanel>
    </StackPanel>
  </StackPanel>
</Border>
"@
    $card = [System.Windows.Markup.XamlReader]::Parse($xml)
    $g.UI = $card
    $g.ArtSet = $false
    foreach ($n in 'Go', 'Undo', 'Tips') { $card.FindName($n).Tag = $g.Id }
    $card.FindName('Go').Add_Click({ param($s, $e) try { Invoke-GamePreset (Get-Game ([string]$s.Tag)) } catch { Write-Log "Game preset error: $_" } })
    $card.FindName('Undo').Add_Click({ param($s, $e) try { Undo-GamePreset (Get-Game ([string]$s.Tag)) } catch { Write-Log "Game undo error: $_" } })
    $card.FindName('Tips').Add_Click({ param($s, $e) $gg = Get-Game ([string]$s.Tag); if ($gg -and -not $gg.Custom) { Open-ProFor $gg.Id } else { Open-ProFor 'other' } })
    $card.RenderTransform = New-Object System.Windows.Media.TranslateTransform
    $card.Add_MouseEnter({ param($s, $e)
            try {
                $s.RenderTransform.BeginAnimation([System.Windows.Media.TranslateTransform]::YProperty, (New-Anim -3 180))
                $b = $s.FindName('Banner').Background
                if ($b -is [System.Windows.Media.ImageBrush]) {
                    $b.RelativeTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, (New-Anim 1.06 400))
                    $b.RelativeTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, (New-Anim 1.06 400))
                }
            } catch { } })
    $card.Add_MouseLeave({ param($s, $e)
            try {
                $s.RenderTransform.BeginAnimation([System.Windows.Media.TranslateTransform]::YProperty, (New-Anim 0 180))
                $b = $s.FindName('Banner').Background
                if ($b -is [System.Windows.Media.ImageBrush]) {
                    $b.RelativeTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, (New-Anim 1 400))
                    $b.RelativeTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, (New-Anim 1 400))
                }
            } catch { } })
    Update-GameCard $g
    Set-GameArt $g
    $card
}

function Get-Game([string]$id) { $Games | Where-Object { $_.Id -eq $id } | Select-Object -First 1 }

function Update-GameCard($g) {
    $c = $g.UI; if (-not $c) { return }
    $applied = $State.misc.ContainsKey("game_$($g.Id)")
    $badge = $c.FindName('Badge'); $bt = $c.FindName('BadgeTxt'); $bd = $c.FindName('BadgeDot'); $info = $c.FindName('Info')
    if ($applied) {
        $bt.Text = 'Optimized'; $bt.Foreground = Get-Brush '#06180E'; $bd.Fill = Get-Brush '#06180E'; $badge.Background = Get-Brush '#EB2ED47A'
    } elseif ($g.Installed) {
        $bt.Text = 'Installed'; $bt.Foreground = Get-Brush '#FFFFFF'; $bd.Fill = Get-Brush '#2ED47A'; $badge.Background = Get-Brush '#B30A0F1C'
    } else {
        $bt.Text = 'Not installed'; $bt.Foreground = Get-Brush '#C9D1E3'; $bd.Fill = Get-Brush '#7F8BA6'; $badge.Background = Get-Brush '#990A0F1C'
    }
    if ($g.Found.Count -gt 0) { $info.Text = $g.Found[0]; $info.ToolTip = ($g.Found -join "`n") }
    elseif ($g.Installed) { $info.Text = 'Installed - Windows tweaks only'; $info.ToolTip = $null }
    else { $info.Text = 'Not found on this PC - Windows tweaks still apply'; $info.ToolTip = $null }
    $u = $c.FindName('Undo')
    if ($g.Custom -or $applied) { $u.Visibility = 'Visible' } else { $u.Visibility = 'Collapsed' }
    if ($applied) { $c.BorderBrush = Get-Brush '#662ED47A' } else { $c.BorderBrush = Get-Brush '#1E2A45' }
    $c.Opacity = 1; if (-not $g.Installed) { $c.Opacity = 0.82 }
}

function Load-Games {
    Show-Overlay 'Searching for installed games (Steam, Epic, Riot, Battle.net, Roblox ...)'
    try {
        $libs = Get-SteamLibraries
        $index = Get-InstallIndex
        $list = New-Object System.Collections.ArrayList
        foreach ($g in $GameCatalog) {
            $g.UI = $null
            try { Find-GameExes $g $libs $index } catch { $g.Found = @(); $g.Installed = $false }
            [void]$list.Add($g)
        }
        foreach ($g in Get-CustomGames) { [void]$list.Add($g) }
        $script:Games = @($list | Sort-Object @{ Expression = { if ($_.Installed) { 0 } else { 1 } } }, @{ Expression = { $_.Name } })
        $GameGrid.Children.Clear()
        foreach ($g in $Games) { [void]$GameGrid.Children.Add((New-GameCard $g)) }
        try { Start-GameArtDownload } catch { Write-Log "Game art download error: $_" }
        $inst = @($Games | Where-Object { $_.Installed }).Count
        $GamesSub.Text = "$inst of $($Games.Count) games found on this PC. Optimize applies a Windows preset plus per-game settings."
        $script:GamesLoaded = $true
        Update-GameWatchList
    } catch { Write-Log "Game scan error: $_" }
    Hide-Overlay
}

function Get-PresetTweaks($g) {
    $ids = $PresetCasual; if ($g.Type -eq 'comp') { $ids = $PresetComp }
    @($ids | ForEach-Object { $TweakById[$_] } | Where-Object { $_ -and -not $_.Active -and (Test-Suitable $_) })
}

function Invoke-GamePreset($g) {
    if (-not $g) { return }
    $tw = Get-PresetTweaks $g
    $lines = New-Object System.Collections.ArrayList
    if ($tw.Count -gt 0) { [void]$lines.Add("- $($tw.Count) Windows optimizations for $(if ($g.Type -eq 'comp') { 'lowest latency' } else { 'smooth frame times' })") }
    else { [void]$lines.Add('- All matching Windows optimizations are already active') }
    if ($g.Found.Count -gt 0) {
        [void]$lines.Add('- Always run the game on the high-performance GPU')
        if ($g.Prio) { [void]$lines.Add('- High CPU priority for the game') }
        if ($g.Fso) { [void]$lines.Add('- Fullscreen optimizations off for the game (lower input lag)') }
    }
    $r = Show-Msg ("Optimize this PC for $($g.Name)?`n`n" + ($lines -join "`n") + "`n`nEverything can be undone.") "Game preset: $($g.Name)" 'YesNo' 'Question'
    if ([string]$r -ne 'Yes') { return }
    if (-not (Ensure-RestorePoint)) { return }
    $i = 0; $fail = 0
    foreach ($t in $tw) {
        $i++
        Show-Overlay ("{0}: {1} of {2}`n{3}" -f $g.Name, $i, $tw.Count, $t.Name)
        if (-not (Set-TweakState $t $true -Quiet)) { $fail++ }
    }
    Show-Overlay "$($g.Name): game settings..."
    $ErrorActionPreference = 'Stop'
    try {
        foreach ($p in $g.Found) {
            Set-Reg $GPUPREF $p 'GpuPreference=2;' 'String'
            if ($g.Fso) {
                $cur = [string](Get-RegValue $LAYERS $p)
                $v = '~ DISABLEDXMAXIMIZEDWINDOWEDMODE'
                if ($cur -and $cur -notmatch 'DISABLEDXMAXIMIZEDWINDOWEDMODE') { if ($cur.StartsWith('~')) { $v = "$cur DISABLEDXMAXIMIZEDWINDOWEDMODE" } else { $v = "~ $cur DISABLEDXMAXIMIZEDWINDOWEDMODE" } }
                elseif ($cur) { $v = $cur }
                Set-Reg $LAYERS $p $v 'String'
            }
            if ($g.Prio) { Set-Reg "$IFEO\$([IO.Path]::GetFileName($p))\PerfOptions" 'CpuPriorityClass' 3 }
        }
        $State.misc["game_$($g.Id)"] = @{ Paths = @($g.Found); Fso = $g.Fso; Prio = $g.Prio; Date = (Get-Date).ToString('yyyy-MM-dd HH:mm') }
        Write-Log "Game preset applied: $($g.Name)"
    } catch {
        Write-Log "Game preset error for $($g.Name): $($_.Exception.Message)"
        Show-Msg "Some game settings for $($g.Name) could not be applied:`n`n$($_.Exception.Message)" 'Silvan Boost' 'OK' 'Warning' | Out-Null
    } finally { Save-State; Hide-Overlay }
    $ErrorActionPreference = 'Continue'
    Update-GameCard $g; Update-Stats; Update-BackupPage
    $msg = "$($g.Name) is optimized."
    if ($fail -gt 0) { $msg += "`n$fail Windows optimization(s) were skipped (not supported here)." }
    if ($RebootPill.Visibility -eq 'Visible') { $msg += "`n`nRestart your PC to finish." }
    $msg += "`n`nTip: click 'Pro settings' on the game card for the best in-game settings."
    Set-Status "$($g.Name) optimized"
    Show-Msg $msg "Game preset: $($g.Name)" | Out-Null
}

function Undo-GamePreset($g) {
    if (-not $g) { return }
    $key = "game_$($g.Id)"
    if ($State.misc.ContainsKey($key)) {
        $m = $State.misc[$key]
        foreach ($p in @($m.Paths)) {
            if (-not $p) { continue }
            Restore-Reg $GPUPREF $p $null
            if ($m.Fso) { Restore-Reg $LAYERS $p $null }
            if ($m.Prio) {
                $ek = "$IFEO\$([IO.Path]::GetFileName($p))"
                Restore-Reg "$ek\PerfOptions" 'CpuPriorityClass' $null
                try { $k = Get-Item -LiteralPath $ek -ErrorAction Stop; if ($k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0) { Remove-Item -LiteralPath $ek -Force } } catch { }
            }
        }
        $State.misc.Remove($key)
        Save-State
        Write-Log "Game preset removed: $($g.Name)"
    }
    if ($g.Custom) {
        $State.misc['CustomGames'] = @(@($State.misc['CustomGames']) | Where-Object { $_ -and $_.Id -ne $g.Id })
        Save-State
        Load-Games
        Set-Status "$($g.Name) removed"
        return
    }
    Update-GameCard $g
    Set-Status "$($g.Name): game settings undone. Windows optimizations stay active (use Revert all to undo those)."
}

function Show-GameTips($g) {
    if (-not $g) { return }
    $ids = $PresetCasual; if ($g.Type -eq 'comp') { $ids = $PresetComp }
    Show-Msg ("Best in-game settings for $($g.Name):`n`n$($g.Tips)`n`n--------`nThe Optimize button applies $($ids.Count) Windows optimizations (only those that suit this PC), plus high-performance GPU" +
        $(if ($g.Prio) { ', high CPU priority' } else { '' }) + $(if ($g.Fso) { ' and fullscreen optimizations off' } else { '' }) + ' for the game.') "Tips: $($g.Name)" | Out-Null
}

function Add-CustomGame {
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Title = 'Choose the game .exe'
    $dlg.Filter = 'Game (*.exe)|*.exe'
    if (-not $dlg.ShowDialog($Window)) { return }
    $p = $dlg.FileName
    $nm = [IO.Path]::GetFileNameWithoutExtension($p)
    $r = Show-Msg "Is '$nm' a competitive / online game?`n`nYes = Competitive preset (lowest input lag and ping)`nNo = Smooth & quality preset (singleplayer / casual)" 'Add game' 'YesNoCancel' 'Question'
    if ([string]$r -eq 'Cancel') { return }
    $type = 'casual'; if ([string]$r -eq 'Yes') { $type = 'comp' }
    $cg = @{ Id = 'custom_' + [guid]::NewGuid().ToString('N').Substring(0, 8); Name = $nm; Exe = $p; Type = $type }
    $State.misc['CustomGames'] = @(@(@($State.misc['CustomGames']) | Where-Object { $_ }) + , $cg)
    Save-State
    Write-Log "Custom game added: $nm"
    Load-Games
}

# ------------------------------------------------------------------ Pro Settings data
function PR($S, $V, $W) { , @($S, $V, $W) }
$script:ProSettings = @{
    'valorant' = @{ Kind = 'pro'; Note = 'Almost every VALORANT pro plays 1080p fullscreen on low settings with an uncapped frame rate - clarity and FPS beat eye candy.'; Rows = @(
        (PR 'Display mode' 'Fullscreen' 'Lowest input lag and highest FPS'),
        (PR 'Resolution' '1920 x 1080' 'The pro standard; native 16:9'),
        (PR 'Limit FPS' 'Off (uncapped)' 'Pros keep FPS uncapped; cap only on weak PCs'),
        (PR 'Material / Texture / Detail quality' 'Low' 'More FPS and less visual clutter'),
        (PR 'UI quality' 'Low' 'No gameplay difference'),
        (PR 'Vignette, Bloom, Distortion, Cast shadows' 'Off' 'Cleaner image, more FPS'),
        (PR 'Anti-aliasing' 'MSAA 2x or None' 'Small clarity gain for little cost'),
        (PR 'Anisotropic filtering' '1x - 4x' 'Barely visible during play'),
        (PR 'VSync' 'Off' 'VSync adds input lag'),
        (PR 'NVIDIA Reflex' 'On + Boost' 'Lowest system latency'),
        (PR 'Multithreaded rendering' 'On' 'Uses more CPU cores = more FPS'),
        (PR 'Enemy highlight color' 'Yellow or Purple' 'Stands out best against most maps')) }
    'cs2' = @{ Kind = 'pro'; Note = 'Most top CS2 pros still play 4:3 stretched (1280 x 960). 16:10 (1600 x 1024) is the popular alternative; native 1080p is fine too - FPS matters more than resolution.'; Rows = @(
        (PR 'Resolution' '1280 x 960 (4:3, stretched)' 'Most used at the top level; wider-looking models'),
        (PR 'Display mode' 'Fullscreen' 'Lowest input lag'),
        (PR 'Boost player contrast' 'Enabled' 'Makes enemies easier to see'),
        (PR 'VSync' 'Disabled' 'Adds input lag'),
        (PR 'NVIDIA Reflex' 'Enabled + Boost' 'Lower system latency'),
        (PR 'Max FPS (fps_max)' '0 (unlimited) or a stable high cap' 'Highest FPS; cap if your frametimes jump around'),
        (PR 'Multisampling (MSAA)' 'None to 4x' 'Pros vary; Off gives the most FPS'),
        (PR 'Shader / Particle / Model-texture detail' 'Low' 'More FPS and less clutter'),
        (PR 'Ambient occlusion' 'Disabled' 'FPS cost, no competitive value'),
        (PR 'High Dynamic Range' 'Performance' 'Cheaper lighting'),
        (PR 'FidelityFX Super Resolution' 'Disabled' 'Upscaling blurs distant enemies'),
        (PR 'Texture filtering' 'Anisotropic 4x - 16x' 'Almost free on modern GPUs')) }
    'fortnite' = @{ Kind = 'pro'; Note = 'Competitive Fortnite players use Performance mode with low view distance and textures for the most stable FPS.'; Rows = @(
        (PR 'Rendering mode' 'Performance' 'Removes heavy effects, lowest CPU and GPU load'),
        (PR 'Window mode' 'Fullscreen' 'Lowest input lag'),
        (PR 'Resolution' '1920 x 1080' 'Most common in competitive play'),
        (PR '3D resolution' '100%' 'Lower it in 10% steps only if FPS are too low'),
        (PR 'View distance' 'Near' 'Recommended for Performance mode'),
        (PR 'Textures / Meshes' 'Low' 'Less VRAM use, steadier FPS'),
        (PR 'Frame rate limit' 'Unlimited (or your refresh rate)' 'Match refresh rate only if you see tearing'),
        (PR 'VSync' 'Off' 'Use G-Sync / FreeSync instead'),
        (PR 'NVIDIA Reflex' 'On + Boost' 'Lowest latency on NVIDIA cards'),
        (PR 'Show FPS' 'On' 'Keep an eye on drops'),
        (PR '3D Headphones / Visualize sound effects' 'On' 'Hear and see where enemies are')) }
    'apex' = @{ Kind = 'pro'; Note = 'Apex pros run a high FOV with nearly everything else on low or disabled - shadows and volumetrics only get in the way.'; Rows = @(
        (PR 'Display mode' 'Full Screen' 'Lowest input lag'),
        (PR 'Field of view' '104 - 110' 'See more of the fight'),
        (PR 'Adaptive resolution FPS target' '0 (off)' 'Keeps the image sharp'),
        (PR 'Anti-aliasing' 'None' 'Large FPS gain, less blur'),
        (PR 'Texture streaming budget' 'By VRAM: 6 GB+ High, 3-4 GB Medium' 'Too high causes stutter'),
        (PR 'Texture filtering' 'Anisotropic 2x' 'Clarity vs. performance'),
        (PR 'Ambient occlusion' 'Disabled' 'Big FPS gain'),
        (PR 'Sun shadow coverage / detail' 'Low' 'Less clutter'),
        (PR 'Spot shadows, volumetric lighting, dynamic spot shadows' 'Disabled' 'More FPS, better visibility'),
        (PR 'Model / effects detail, ragdolls' 'Low' 'Clearer enemies, less CPU load'),
        (PR 'Impact marks' 'Low' 'Keeps some hit feedback'),
        (PR 'NVIDIA Reflex' 'Enabled + Boost' 'Lower latency'),
        (PR 'Launch options' '+fps_max 0' 'Removes the FPS cap (engine max is about 300)')) }
    'lol' = @{ Kind = 'pro'; Note = 'League pros play fullscreen with a high frame rate and low effects; almost all of them use an unlocked camera.'; Rows = @(
        (PR 'Window mode' 'Full screen' 'Lowest input lag'),
        (PR 'Resolution' 'Native (usually 1920 x 1080)' 'Sharp UI'),
        (PR 'Frame rate cap' 'Uncapped or 240' 'Smooth camera movement'),
        (PR 'Wait for vertical sync' 'Off' 'Adds input lag'),
        (PR 'Anti-aliasing' 'Off' 'Free FPS'),
        (PR 'Shadows' 'Off' 'No competitive value'),
        (PR 'Effects / Environment quality' 'Low - Medium' 'Less clutter in team fights'),
        (PR 'Character inking' 'Off' 'Cleaner models'),
        (PR 'Hide eye candy' 'On' 'Less distraction'),
        (PR 'Camera lock mode' 'Unlocked (semi-locked)' 'What nearly all pros use')) }
    'ow2' = @{ Kind = 'pro'; Note = 'Overwatch pros use maximum FOV, 100% render scale and low effects, with Reflex and Reduce Buffering on.'; Rows = @(
        (PR 'Display mode' 'Fullscreen' 'Lower latency than borderless'),
        (PR 'Field of view' '103 (max)' 'See more'),
        (PR 'Render scale' 'Custom 100%' 'Sharp image; avoid Automatic'),
        (PR 'Dynamic render scale' 'Off' 'Keeps clarity constant'),
        (PR 'Frame rate' 'Custom 600, or 3-4 below refresh with G-Sync' 'Low latency without tearing'),
        (PR 'NVIDIA Reflex' 'Enabled + Boost' 'Lower latency'),
        (PR 'Reduce buffering' 'On' 'Lower input lag'),
        (PR 'VSync / Triple buffering' 'Off' 'Add input lag'),
        (PR 'Texture quality' 'Medium' 'Good look, low cost'),
        (PR 'Texture filtering' '16x' 'Almost free'),
        (PR 'Shadow detail' 'Medium' 'Some shadows help read fights'),
        (PR 'Model / Effects / Lighting detail' 'Low' 'Less clutter, more FPS'),
        (PR 'Anti-alias, local fog, dynamic reflections, ambient occlusion' 'Off / Low' 'Free FPS')) }
    'rocket' = @{ Kind = 'pro'; Note = 'Rocket League pros play on performance graphics with a fast, high camera and camera shake off.'; Rows = @(
        (PR 'Camera shake' 'Off' 'Smoother view'),
        (PR 'Field of view' '110' 'See more of the field'),
        (PR 'Camera distance / height / angle' '260 - 280 / 90 - 110 / -3 to -5' 'Typical pro range'),
        (PR 'Stiffness / swivel / transition' '0.40 - 0.50 / 4.0 - 6.0 / 1.0 - 1.5' 'Responsive camera'),
        (PR 'Ball camera' 'Toggle' 'Fewer button presses'),
        (PR 'Display mode' 'Fullscreen, 1920 x 1080' 'Lowest input lag'),
        (PR 'Vertical sync' 'Off' 'Adds input lag'),
        (PR 'Frame rate' 'Match or exceed your refresh rate' 'Smooth gameplay'),
        (PR 'Render quality / detail' 'High Performance' 'More FPS'),
        (PR 'Texture / world / particle detail' 'Performance' 'More FPS, less clutter'),
        (PR 'AA, AO, depth of field, bloom, light shafts, lens flares, motion blur, weather, dynamic shadows' 'Off' 'Cleaner picture'),
        (PR 'Transparent goalposts' 'On' 'See the field from inside your goal')) }
    'r6' = @{ Kind = 'pro'; Note = 'Siege pros keep shadows on (they reveal enemies) but turn off lens effects and depth of field; the Vulkan version often runs faster.'; Rows = @(
        (PR 'Version' 'Vulkan' 'Often higher and steadier FPS'),
        (PR 'Display mode' 'Fullscreen' 'Lowest input lag'),
        (PR 'Field of view' '84 - 90' 'Common pro range'),
        (PR 'NVIDIA Reflex' 'On + Boost' 'Lower latency'),
        (PR 'VSync' 'Off' 'Adds input lag'),
        (PR 'Texture quality' 'Medium - High (by VRAM)' 'Little FPS impact'),
        (PR 'LOD / Shading / Reflections' 'Low' 'More FPS'),
        (PR 'Shadow quality' 'Medium' 'Shadows show enemy movement'),
        (PR 'Ambient occlusion' 'Off' 'More FPS'),
        (PR 'Lens effects / Zoom-in depth of field' 'Off' 'Clearer aim'),
        (PR 'Render scaling' '100' 'Sharp image')) }
    'pubg' = @{ Kind = 'pro'; Note = 'PUBG pros put anti-aliasing and view distance high for spotting, and everything else very low.'; Rows = @(
        (PR 'Display mode' 'Fullscreen' 'Lowest input lag'),
        (PR 'Screen scale' '100' 'Sharp image'),
        (PR 'Anti-aliasing' 'High - Ultra' 'Less shimmering on distant enemies'),
        (PR 'View distance' 'Medium - Ultra' 'See far-away players and vehicles'),
        (PR 'Post-processing, shadows, effects, foliage' 'Very Low' 'More FPS, less grass cover'),
        (PR 'Textures' 'Medium - Ultra (by VRAM)' 'Little FPS impact'),
        (PR 'Sharpen' 'On' 'Crisper image'),
        (PR 'FPS cap' 'Unlimited' 'Lowest latency'),
        (PR 'FPP camera FOV' '103' 'See more')) }
    'rivals' = @{ Kind = 'pro'; Note = 'Competitive Marvel Rivals players turn off frame generation and heavy lighting, and keep Reflex on.'; Rows = @(
        (PR 'Display mode' 'Fullscreen' 'Lowest input lag'),
        (PR 'NVIDIA Reflex' 'On + Boost' 'Lower latency'),
        (PR 'Frame generation' 'Off' 'Adds latency'),
        (PR 'Upscaling' 'Native / DLAA, or DLSS Quality for FPS' 'Balance clarity and FPS'),
        (PR 'Global illumination / Reflections' 'Low' 'Big FPS gain'),
        (PR 'Shadows / Effects / Post-processing' 'Low' 'Less clutter'),
        (PR 'Texture quality' 'Medium - High (by VRAM)' 'Small FPS cost'),
        (PR 'VSync' 'Off' 'Adds input lag')) }
    'cod' = @{ Kind = 'pro'; Note = 'Call of Duty players use a high FOV, Reflex and low effects; on-demand texture streaming off avoids hitches.'; Rows = @(
        (PR 'Display mode' 'Fullscreen exclusive' 'Lowest input lag'),
        (PR 'NVIDIA Reflex' 'On + Boost' 'Lower latency'),
        (PR 'Field of view' '100 - 120, ADS FOV: Affected' 'See more'),
        (PR 'Upscaling' 'Off, or DLSS Quality' 'Sharp image'),
        (PR 'Texture resolution' 'High (by VRAM)' 'Little FPS cost'),
        (PR 'Particle / shadow quality' 'Low' 'More FPS, less clutter'),
        (PR 'Screen space shadows / reflections, ambient occlusion' 'Off' 'More FPS'),
        (PR 'Depth of field, motion blur, film grain' 'Off / 0' 'Clearer image'),
        (PR 'On-demand texture streaming' 'Off' 'Avoids streaming hitches')) }
    'rust' = @{ Kind = 'perf'; Note = 'Rust is very CPU-heavy. These settings give the best FPS while keeping players visible.'; Rows = @(
        (PR 'Graphics quality' '1 - 3' 'Biggest FPS lever'),
        (PR 'Shadow quality' '1' 'Big FPS gain'),
        (PR 'Water quality / reflections' '0' 'More FPS'),
        (PR 'Grass displacement' 'Off' 'More FPS'),
        (PR 'Max gibs' '0' 'Fewer physics objects'),
        (PR 'Anti-aliasing' 'Off or FXAA' 'More FPS'),
        (PR 'Particle quality' 'Low' 'Less clutter'),
        (PR 'FPS limit' 'Unlimited (-1)' 'Highest FPS')) }
    'minecraft' = @{ Kind = 'perf'; Note = 'The best Minecraft FPS boost is a performance mod: Sodium (with Fabric) often doubles FPS.'; Rows = @(
        (PR 'Performance mod' 'Sodium (Fabric)' 'Often 2-3x more FPS'),
        (PR 'Render distance' '12 - 16 chunks' 'Big FPS lever'),
        (PR 'Simulation distance' '6 - 8' 'Less CPU load'),
        (PR 'Graphics' 'Fast' 'More FPS'),
        (PR 'Clouds / entity shadows' 'Off' 'More FPS'),
        (PR 'VSync' 'Off' 'Less input lag'),
        (PR 'Max framerate' 'Unlimited' 'Highest FPS'),
        (PR 'Allocated RAM (launcher)' '4 - 6 GB' 'Never more than half your RAM')) }
    'roblox' = @{ Kind = 'perf'; Note = 'Roblox caps FPS at 60 by default - unlock it first.'; Rows = @(
        (PR 'Maximum frame rate' 'Your monitor refresh rate' 'Removes the 60 FPS cap'),
        (PR 'Graphics mode' 'Manual' 'Stops automatic quality jumps'),
        (PR 'Graphics quality' '3 - 6 (lower in busy games)' 'Roblox is often CPU-limited'),
        (PR 'Fullscreen' 'On (F11)' 'Lower input lag'),
        (PR 'Browser tabs' 'Close while playing' 'Frees CPU and RAM')) }
    'gta5' = @{ Kind = 'perf'; Note = 'GTA V has a few settings that cost a lot of FPS for very little visual gain.'; Rows = @(
        (PR 'Grass quality' 'High (not Ultra)' 'Ultra costs a lot of FPS'),
        (PR 'MSAA' 'Off - use FXAA, or DLSS in the Enhanced edition' 'Big FPS gain'),
        (PR 'Reflection MSAA' 'Off' 'More FPS'),
        (PR 'Population / distance scaling' '50 - 70%' 'Less CPU load'),
        (PR 'Extended distance scaling' 'Low' 'Big FPS gain'),
        (PR 'Shadow quality' 'High, soft shadows: Sharp' 'Good look, lower cost'),
        (PR 'Motion blur' '0' 'Clearer image')) }
    'eafc' = @{ Kind = 'pro'; Note = 'Competitive FC players care most about the camera and a stable frame rate.'; Rows = @(
        (PR 'Camera' 'Tele Broadcast or Co-op' 'Most popular competitive cameras'),
        (PR 'Camera height / zoom' 'Low (0 - 20) / 0 - 10' 'Typical competitive values'),
        (PR 'Display mode' 'Fullscreen' 'Lower input lag'),
        (PR 'VSync' 'Off with G-Sync/FreeSync, else On' 'Avoid tearing without extra lag'),
        (PR 'Dynamic resolution' 'Off' 'Stable image'),
        (PR 'Rendering quality' 'High' 'FC runs well on most GPUs')) }
    'cyberpunk' = @{ Kind = 'perf'; Note = 'For Cyberpunk, upscaling and a few heavy settings decide almost everything.'; Rows = @(
        (PR 'DLSS / FSR' 'Quality or Balanced' 'Big FPS gain'),
        (PR 'Frame generation' 'On only on RTX 40/50 for singleplayer' 'Smoother, adds some latency'),
        (PR 'Ray tracing' 'Off, or Medium with DLSS' 'Huge FPS cost'),
        (PR 'Screen space reflections' 'Medium' 'Psycho costs a lot'),
        (PR 'Volumetric fog / cascaded shadows' 'Medium' 'Big FPS gain'),
        (PR 'Crowd density' 'Medium' 'Less CPU load'),
        (PR 'Motion blur, film grain, chromatic aberration' 'Off' 'Clearer image')) }
    'other' = @{ Kind = 'perf'; Note = 'General settings that give the best performance in almost every game.'; Rows = @(
        (PR 'Display mode' 'Fullscreen' 'Lowest input lag'),
        (PR 'VSync' 'Off (use G-Sync / FreeSync)' 'Adds input lag'),
        (PR 'NVIDIA Reflex / AMD Anti-Lag' 'On (+ Boost)' 'Lower latency'),
        (PR 'Frame cap' 'Refresh rate or higher; 3 below refresh with G-Sync' 'Smooth and low latency'),
        (PR 'Upscaling' 'DLSS / FSR Quality if FPS are low' 'Cheap FPS'),
        (PR 'Motion blur, film grain, depth of field' 'Off' 'Clearer image'),
        (PR 'Shadows / volumetrics / ambient occlusion' 'Low - Medium' 'Most expensive effects'),
        (PR 'Textures' 'As high as your VRAM allows' 'Almost no FPS cost')) }
}
$script:ProSel = $null
$script:ProChipMap = @{}

function Build-ProChips {
    $ProChips.Children.Clear(); $ProChipMap.Clear()
    $items = @($GameCatalog | ForEach-Object { @{ Id = $_.Id; Name = $_.Name } }) + , @{ Id = 'other'; Name = 'Other games' }
    foreach ($it in $items) {
        $rb = New-Object System.Windows.Controls.RadioButton
        $rb.Content = $it.Name; $rb.GroupName = 'pro'; $rb.Tag = $it.Id
        $rb.Style = $Window.FindResource('Chip')
        $rb.Margin = [System.Windows.Thickness]::new(0, 0, 8, 8)
        $rb.Add_Checked({ param($s, $e) Show-ProSettings ([string]$s.Tag) })
        $ProChipMap[$it.Id] = $rb
        [void]$ProChips.Children.Add($rb)
    }
}

function Show-ProSettings([string]$id) {
    $d = $ProSettings[$id]; if (-not $d) { $d = $ProSettings['other']; $id = 'other' }
    $script:ProSel = $id
    $name = 'Other games'
    $g = $GameCatalog | Where-Object { $_.Id -eq $id } | Select-Object -First 1
    if ($g) { $name = $g.Name }
    $ProTitle.Text = $name
    if ($d.Kind -eq 'pro') { $ProKind.Text = 'Pro settings'; $ProKindBadge.Background = Get-Brush '#26FF8A1F'; $ProKind.Foreground = Get-Brush '#FFB06A' }
    else { $ProKind.Text = 'Best performance settings'; $ProKindBadge.Background = Get-Brush '#1A3B82F6'; $ProKind.Foreground = Get-Brush '#7AA7FF' }
    $ProNote.Text = $d.Note
    $BtnProOptimize.Visibility = $(if ($g) { 'Visible' } else { 'Collapsed' })
    $BtnProOpen.Visibility = $(if ($d.Kind -eq 'pro') { 'Visible' } else { 'Collapsed' })
    try { Update-ProCfgBar $id } catch { }
    $ProTable.Children.Clear()
    $hdr = "<Grid $NS><Grid.ColumnDefinitions><ColumnDefinition Width=`"2*`"/><ColumnDefinition Width=`"2*`"/><ColumnDefinition Width=`"3*`"/></Grid.ColumnDefinitions>" +
        "<TextBlock Text=`"SETTING`" FontSize=`"11`" FontWeight=`"SemiBold`" Foreground=`"#7F8BA6`" Margin=`"0,0,12,8`"/>" +
        "<TextBlock Grid.Column=`"1`" Text=`"USE THIS`" FontSize=`"11`" FontWeight=`"SemiBold`" Foreground=`"#7F8BA6`" Margin=`"0,0,12,8`"/>" +
        "<TextBlock Grid.Column=`"2`" Text=`"WHY`" FontSize=`"11`" FontWeight=`"SemiBold`" Foreground=`"#7F8BA6`" Margin=`"0,0,0,8`"/></Grid>"
    [void]$ProTable.Children.Add([System.Windows.Markup.XamlReader]::Parse($hdr))
    foreach ($r in $d.Rows) {
        $x = "<Grid $NS><Grid.ColumnDefinitions><ColumnDefinition Width=`"2*`"/><ColumnDefinition Width=`"2*`"/><ColumnDefinition Width=`"3*`"/></Grid.ColumnDefinitions>" +
            "<Border Grid.ColumnSpan=`"3`" BorderBrush=`"#1A2440`" BorderThickness=`"0,1,0,0`"/>" +
            "<TextBlock Text=`"$(X $r[0])`" FontSize=`"13`" FontWeight=`"SemiBold`" TextWrapping=`"Wrap`" Margin=`"0,10,12,10`"/>" +
            "<TextBlock Grid.Column=`"1`" Text=`"$(X $r[1])`" FontSize=`"13`" FontWeight=`"SemiBold`" Foreground=`"#FFB06A`" TextWrapping=`"Wrap`" Margin=`"0,10,12,10`"/>" +
            "<TextBlock Grid.Column=`"2`" Text=`"$(X $r[2])`" FontSize=`"12.5`" Foreground=`"#9AA5BF`" TextWrapping=`"Wrap`" Margin=`"0,10,0,10`"/></Grid>"
        [void]$ProTable.Children.Add([System.Windows.Markup.XamlReader]::Parse($x))
    }
}

function Open-ProFor([string]$id) {
    if (-not $ProSettings.ContainsKey($id)) { $id = 'other' }
    $NavPro.IsChecked = $true
    $rb = $ProChipMap[$id]
    if ($rb) { if ($rb.IsChecked) { Show-ProSettings $id } else { $rb.IsChecked = $true } }
}

# ------------------------------------------------------------------ Live Monitor
$script:PresentMonPath = Join-Path $PSScriptRoot 'PresentMon.exe'
if (-not (Test-Path -LiteralPath $PresentMonPath)) { $PresentMonPath = Join-Path $env:ProgramData 'SilvanBoost\app\PresentMon.exe' }
$script:LiveSession = $null
$script:LiveSamples = New-Object System.Collections.ArrayList
$script:LiveProblems = @{}
$script:LiveTick = 0
$script:BgHints = @{
    'msmpeng' = 'Microsoft Defender is scanning. Let it finish, or schedule scans for when you are not gaming (do not turn Defender off).'
    'tiworker' = 'Windows Update is installing updates in the background. Let it finish, then restart.'
    'trustedinstaller' = 'Windows Update is installing updates in the background. Let it finish, then restart.'
    'searchindexer' = 'Windows Search is indexing files. The "Disable Search Indexing" optimization stops this.'
    'chrome' = 'Browser tabs (videos, streams, many tabs) use CPU. Close them while gaming.'
    'msedge' = 'Browser tabs (videos, streams, many tabs) use CPU. Close them while gaming.'
    'firefox' = 'Browser tabs (videos, streams, many tabs) use CPU. Close them while gaming.'
    'opera' = 'Browser tabs use CPU. Close them while gaming.'
    'brave' = 'Browser tabs use CPU. Close them while gaming.'
    'discord' = 'Discord: turn off Hardware Acceleration and the in-game overlay in Discord settings.'
    'obs64' = 'OBS is recording or streaming. Use the NVENC / AMF hardware encoder to take load off the CPU.'
    'steamwebhelper' = 'Steam''s browser/overlay. Close the Steam store window while gaming.'
    'onedrive' = 'OneDrive is syncing files. Pause syncing while gaming.'
    'wallpaper64' = 'Wallpaper Engine: set it to pause while other apps are fullscreen.'
    'svchost' = 'A Windows service is busy (often Windows Update or the Delivery Optimization service).'
}

function Update-GameWatchList {
    $h = [hashtable]::Synchronized(@{})
    foreach ($g in $GameCatalog) {
        foreach ($e in $g.Exes) { if ($e) { $h[[IO.Path]::GetFileNameWithoutExtension($e).ToLower()] = @{ Name = $g.Name; Exe = $e; Id = $g.Id } } }
    }
    foreach ($c in @($State.misc['CustomGames'])) {
        if ($c -and $c.Exe) {
            $e = [IO.Path]::GetFileName([string]$c.Exe)
            $h[[IO.Path]::GetFileNameWithoutExtension($e).ToLower()] = @{ Name = [string]$c.Name; Exe = $e; Id = [string]$c.Id }
        }
    }
    $Sync.Watch = $h
}

function Start-PresentMon([string]$exe) {
    Stop-PresentMon
    $Sync.Fps = 0.0; $Sync.Low1 = 0.0; $Sync.InputLat = 0.0; $Sync.FrameMs = 0.0; $Sync.StutterTotal = 0; $Sync.FrameHist = @()
    if (-not (Test-Path -LiteralPath $PresentMonPath)) { $Sync.PmState = 'missing'; return }
    $Sync.PmRun = $true; $Sync.PmState = 'starting'
    $rs = [runspacefactory]::CreateRunspace(); $rs.Open()
    $rs.SessionStateProxy.SetVariable('Sync', $Sync)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        param($pm, $exe)
        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        $p = $null
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $pm
            $psi.Arguments = "--process_name `"$exe`" --output_stdout --stop_existing_session --session_name SilvanBoostPM --terminate_on_proc_exit --v2_metrics"
            $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
            $p = [System.Diagnostics.Process]::Start($psi)
            $Sync.PmProc = $p
            $null = $p.StandardError.ReadToEndAsync()
            $col = -1; $scCol = -1; $latCol = -1
            $lat = New-Object 'System.Collections.Generic.List[double]'
            $ft = New-Object 'System.Collections.Generic.List[double]'
            $swCounts = @{}; $main = $null; $med = 16.7
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $Sync.PmState = 'running'
            while ($Sync.PmRun) {
                $line = $p.StandardOutput.ReadLine()
                if ($null -eq $line) { break }
                if ($col -lt 0) {
                    $h = $line.Split(',')
                    for ($k = 0; $k -lt $h.Length; $k++) {
                        $n = $h[$k].Trim()
                        if ($n -ieq 'msBetweenPresents') { $col = $k }
                        if ($n -ieq 'SwapChainAddress') { $scCol = $k }
                        if ($n -ieq 'MsAllInputToPhotonLatency') { $latCol = $k }
                    }
                    if ($col -lt 0) { for ($k = 0; $k -lt $h.Length; $k++) { if ($h[$k].Trim() -ieq 'FrameTime') { $col = $k } } }
                    continue
                }
                $f = $line.Split(',')
                if ($f.Length -le $col) { continue }
                if ($scCol -ge 0 -and $f.Length -gt $scCol) {
                    $s = $f[$scCol]
                    $swCounts[$s] = 1 + [int]$swCounts[$s]
                    if (-not $main -or $swCounts[$s] -gt 2 * [int]$swCounts[$main]) { $main = $s }
                    if ($s -ne $main) { continue }
                }
                if ($latCol -ge 0 -and $f.Length -gt $latCol) {
                    $lv = 0.0
                    if ([double]::TryParse($f[$latCol], [System.Globalization.NumberStyles]::Float, $inv, [ref]$lv) -and $lv -gt 0 -and $lv -lt 500) {
                        $lat.Add($lv); if ($lat.Count -gt 60) { $lat.RemoveAt(0) }
                    }
                }
                $v = 0.0
                if (-not [double]::TryParse($f[$col], [System.Globalization.NumberStyles]::Float, $inv, [ref]$v)) { continue }
                if ($v -le 0 -or $v -gt 2000) { continue }
                if ($ft.Count -ge 60 -and $v -gt [Math]::Max(2.5 * $med, $med + 15)) { $Sync.StutterTotal = [int]$Sync.StutterTotal + 1 }
                $ft.Add($v)
                if ($ft.Count -gt 1500) { $ft.RemoveRange(0, $ft.Count - 1500) }
                if ($sw.ElapsedMilliseconds -ge 250) {
                    $sw.Restart()
                    $sum = 0.0; $n = 0
                    for ($k = $ft.Count - 1; $k -ge 0 -and $sum -lt 1000; $k--) { $sum += $ft[$k]; $n++ }
                    if ($n -gt 0 -and $sum -gt 0) { $Sync.Fps = $n * 1000.0 / $sum; $Sync.FrameMs = $sum / $n }
                    $arr = $ft.ToArray(); [Array]::Sort($arr)
                    $med = $arr[[int][Math]::Floor($arr.Length / 2)]
                    if ($arr.Length -ge 100) { $Sync.Low1 = 1000.0 / $arr[[int][Math]::Floor(($arr.Length - 1) * 0.99)] } else { $Sync.Low1 = 0.0 }
                    if ($lat.Count -ge 3) { $la = $lat.ToArray(); [Array]::Sort($la); $Sync.InputLat = $la[[int][Math]::Floor($la.Length / 2)] }
                    $take = [Math]::Min(150, $ft.Count)
                    $Sync.FrameHist = $ft.GetRange($ft.Count - $take, $take).ToArray()
                }
            }
        } catch { $Sync.PmState = "error: $($_.Exception.Message)" }
        finally {
            try { if ($p -and -not $p.HasExited) { $p.Kill() } } catch { }
            if ($Sync.PmState -eq 'running') { $Sync.PmState = 'stopped' }
        }
    }).AddArgument($PresentMonPath).AddArgument($exe)
    $script:PmPs = $ps
    $script:PmHandle = $ps.BeginInvoke()
}

function Stop-PresentMon {
    $Sync.PmRun = $false
    try { if ($Sync.PmProc -and -not $Sync.PmProc.HasExited) { $Sync.PmProc.Kill() } } catch { }
    $Sync.PmProc = $null
}

function Draw-LiveGraph {
    $hist = @($Sync.FrameHist)
    $w = $LiveGraph.ActualWidth; $h = $LiveGraph.ActualHeight
    if ($w -le 0 -or $hist.Count -lt 2) { $LiveLine.Points = $null; return }
    $sorted = [double[]]$hist.Clone(); [Array]::Sort($sorted)
    $top = [Math]::Max(25.0, $sorted[$sorted.Length - 1] * 1.15)
    $step = $w / 149
    $start = 150 - $hist.Count
    $pts = New-Object System.Windows.Media.PointCollection
    for ($i = 0; $i -lt $hist.Count; $i++) {
        $pts.Add([System.Windows.Point]::new(($start + $i) * $step, $h - ([Math]::Min($hist[$i], $top) / $top) * ($h - 4) - 2))
    }
    $LiveLine.Points = $pts
    $LiveGraphMax.Text = '{0:0} ms' -f $top
}

function Start-LiveSession([string]$key) {
    $w = $Sync.Watch[$key]; if (-not $w) { return }
    $script:LiveSession = @{ Name = $w.Name; Exe = $w.Exe; Id = $w.Id; Start = Get-Date; FpsSum = 0.0; FpsN = 0; LowSum = 0.0; LowN = 0
        TempMax = 0.0; GpuSum = 0.0; CpuSum = 0.0; N = 0; Problems = 0; LatSum = 0.0; LatN = 0 }
    [void]$LiveSamples.Clear(); $LiveProblems.Clear()
    $LiveProbList.Children.Clear(); $LiveEmpty.Visibility = 'Visible'
    $LiveDot.Fill = Get-Brush '#2ED47A'; $LiveDot.Visibility = 'Visible'
    Start-PresentMon $w.Exe
    try { Enter-GameNetMode } catch { Write-Log "Game network mode error: $_" }
    try { Enter-AutoGameMode $w } catch { Write-Log "Auto game mode error: $_" }
    $LiveTitle.Text = "Monitoring $($w.Name) - started $((Get-Date).ToString('HH:mm'))"
    $LiveState.Text = 'LIVE'; $LiveStateBadge.Background = Get-Brush '#262ED47A'; $LiveState.Foreground = Get-Brush '#5BE39A'
    Write-Log "Live monitor: $($w.Name) detected, monitoring started."
    Set-Status "Live monitor: watching $($w.Name)"
}

function End-LiveSession {
    $s = $LiveSession; if (-not $s) { return }
    Stop-PresentMon
    try { Exit-AutoGameMode } catch { }
    try { Exit-GameNetMode } catch { Write-Log "Game network mode error: $_" }
    $dur = (Get-Date) - $s.Start
    $avgFps = 0; if ($s.FpsN -gt 0) { $avgFps = $s.FpsSum / $s.FpsN }
    $avgLow = 0; if ($s.LowN -gt 0) { $avgLow = $s.LowSum / $s.LowN }
    $avgGpu = 0; $avgCpu = 0; if ($s.N -gt 0) { $avgGpu = $s.GpuSum / $s.N; $avgCpu = $s.CpuSum / $s.N }
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add(("{0} - played {1:0} min, ended {2}" -f $s.Name, $dur.TotalMinutes, (Get-Date).ToString('HH:mm')))
    if ($avgFps -gt 0) { [void]$lines.Add(("Average {0:0} FPS, 1% low {1:0} FPS" -f $avgFps, $avgLow)) }
    if ($s.LatN -gt 0) { [void]$lines.Add(("Average PC latency (input to display) {0:0} ms" -f ($s.LatSum / $s.LatN))) }
    [void]$lines.Add(("Average GPU load {0:0}%, CPU load {1:0}%, hottest GPU {2:0} {3}C" -f $avgGpu, $avgCpu, $s.TempMax, [char]176))
    if ($LiveProblems.Count -gt 0) {
        [void]$lines.Add("$($LiveProblems.Count) problem(s) found:")
        foreach ($p in $LiveProblems.Values) { [void]$lines.Add(" - $($p.Title)") }
    } else { [void]$lines.Add('No problems found - your PC handled this game well.') }
    $txt = $lines -join "`n"
    try { Add-GameHistory $s $avgFps $avgLow $(if ($s.LatN -gt 0) { $s.LatSum / $s.LatN } else { 0 }) $dur.TotalMinutes; Build-History } catch { Write-Log "History error: $_" }
    $LiveLastText.Text = $txt
    $LiveLastCard.Visibility = 'Visible'
    Write-Log ("Live session report: " + ($lines -join ' | '))
    $script:LiveSession = $null
    $LiveTitle.Text = 'Waiting for a game... Start any game from Game Presets and it is detected automatically.'
    $LiveState.Text = 'IDLE'; $LiveStateBadge.Background = Get-Brush '#1A2440'; $LiveState.Foreground = Get-Brush '#A9B3CC'
    if ($LiveProblems.Count -eq 0) { $LiveDot.Visibility = 'Collapsed' }
    Set-Status "Live monitor: $($s.Name) closed - session report ready"
    if ($dur.TotalSeconds -ge 30) {
        if ($script:BenchRun -or $script:BenchFocus) { $script:BenchFocus = $false; $NavBench.IsChecked = $true } else { $NavLive.IsChecked = $true }
        try {
            if ($Window.WindowState -eq 'Minimized') { $Window.WindowState = 'Normal' }
            $Window.Activate() | Out-Null
            $Window.Topmost = $true; $Window.Topmost = $false
        } catch { }
    }
}

function Add-LiveProblem([string]$id, [string]$sev, [string]$title, [string]$cause, [string]$fix) {
    if ($LiveProblems.ContainsKey($id)) {
        $p = $LiveProblems[$id]; $p.Count++
        if ($p.Seen) { $p.Seen.Text = "Seen $($p.Count)x - last at $((Get-Date).ToString('HH:mm:ss'))" }
        return
    }
    switch ($sev) {
        'err'  { $g = '&#xE7BA;'; $bg = '#1FEF4444'; $fg = '#F87171' }
        'warn' { $g = '&#xE7BA;'; $bg = '#1FF59E0B'; $fg = '#FBBF24' }
        default { $g = '&#xE946;'; $bg = '#1F3B82F6'; $fg = '#7AA7FF' }
    }
    $xml = @"
<Border $NS Style="{DynamicResource Card}" Padding="14" Margin="0,0,0,10">
  <DockPanel>
    <Border DockPanel.Dock="Left" Width="32" Height="32" CornerRadius="16" Background="$bg" VerticalAlignment="Top">
      <TextBlock Text="$g" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="13" Foreground="$fg" HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
    <StackPanel Margin="12,0,0,0">
      <DockPanel>
        <TextBlock x:Name="Seen" DockPanel.Dock="Right" Text="$((Get-Date).ToString('HH:mm:ss'))" FontSize="11" Foreground="#7F8BA6" VerticalAlignment="Center"/>
        <TextBlock Text="$(X $title)" FontWeight="SemiBold" FontSize="14" TextWrapping="Wrap" Margin="0,0,10,0"/>
      </DockPanel>
      <TextBlock TextWrapping="Wrap" FontSize="12.5" Margin="0,5,0,0" Foreground="#A9B3CC"><Run Text="Why: " FontWeight="SemiBold" Foreground="#E8ECF5"/><Run Text="$(X $cause)"/></TextBlock>
      <TextBlock TextWrapping="Wrap" FontSize="12.5" Margin="0,4,0,0" Foreground="#A9B3CC"><Run Text="Fix: " FontWeight="SemiBold" Foreground="#5BE39A"/><Run Text="$(X $fix)"/></TextBlock>
    </StackPanel>
  </DockPanel>
</Border>
"@
    $row = [System.Windows.Markup.XamlReader]::Parse($xml)
    $LiveProblems[$id] = @{ Id = $id; Title = $title; Count = 1; Seen = $row.FindName('Seen') }
    $LiveProbList.Children.Insert(0, $row)
    $LiveEmpty.Visibility = 'Collapsed'
    $LiveDot.Fill = Get-Brush '#FF8A1F'; $LiveDot.Visibility = 'Visible'
    if ($LiveSession) { $LiveSession.Problems++ }
    $gn = ''; if ($LiveSession) { $gn = $LiveSession.Name }
    Write-Log "Live problem [$gn]: $title - $cause"
}

function Count-Samples([scriptblock]$cond) {
    $n = 0
    foreach ($s in $LiveSamples) { if (& $cond $s) { $n++ } }
    $n
}

function Test-LiveRules {
    if ($LiveSamples.Count -lt 6) { return }
    $last = $LiveSamples[$LiveSamples.Count - 1]
    $need = 5
    $fpsKnown = ($last.Fps -gt 0)

    $hot = Count-Samples { param($s) $s.Temp -ge 83 }
    if ($hot -ge $need) {
        $sev = 'warn'; if ($last.Temp -ge 90) { $sev = 'err' }
        Add-LiveProblem 'gpu-hot' $sev ("Graphics card is running hot ({0:0} {1}C)" -f $last.Temp, [char]176) `
            'Hot GPUs lower their clock speed (thermal throttling) and lose FPS. Usual causes: dust in the cooler, poor case airflow or a flat fan curve.' `
            'Clean the GPU fans and dust filters, improve case airflow, set a more aggressive fan curve (e.g. MSI Afterburner), or cap FPS to your refresh rate.'
    }
    if ((Count-Samples { param($s) $s.Thermal }) -ge $need) {
        Add-LiveProblem 'gpu-throttle' 'warn' 'Graphics card is thermal throttling' 'The GPU driver reports it is slowing down because of temperature.' 'Improve cooling (fans, airflow, dust) - see the temperature tip above.'
    }
    $cpuLim = Count-Samples { param($s) $s.Gpu -ge 0 -and $s.Gpu -lt 85 -and ($s.Core -ge 95 -or $s.Cpu -ge 90) }
    if ($cpuLim -ge $need) {
        Add-LiveProblem 'cpu-bound' 'warn' 'CPU limit - the graphics card is waiting for the CPU' `
            ("One or more CPU cores are maxed out (busiest core {0:0}%) while the GPU only runs at {1:0}%. The game is CPU-bound right now." -f $last.Core, $last.Gpu) `
            'Lower CPU-heavy settings (view distance, crowd/NPC density, physics, shadows), close background apps, make sure XMP/EXPO is on, and apply the Max performance preset.'
    }
    if ((Count-Samples { param($s) $s.Gpu -ge 97 }) -ge 7) {
        Add-LiveProblem 'gpu-bound' 'info' 'GPU limit - the graphics card is at 100%' `
            'Your graphics card is the limit. That is normal at high settings, but a fully loaded GPU adds input lag.' `
            'For competitive games: lower graphics settings or use DLSS / FSR, and turn on NVIDIA Reflex (On + Boost) or AMD Anti-Lag.'
    }
    if ((Count-Samples { param($s) $s.VramTot -gt 0 -and $s.Vram / $s.VramTot -ge 0.95 }) -ge $need) {
        Add-LiveProblem 'vram-full' 'warn' ("Graphics memory is full ({0:0.0} of {1:0} GB VRAM)" -f $last.Vram, $last.VramTot) `
            'Textures no longer fit into the graphics memory and are swapped in and out - this causes stutter.' `
            'Lower texture quality or the texture streaming budget one step, and close browsers or videos running in the background.'
    }
    if ((Count-Samples { param($s) $s.Ram -ge 90 }) -ge $need) {
        Add-LiveProblem 'ram-full' 'warn' ("System memory almost full ({0:0}%)" -f $last.Ram) `
            'Windows starts moving data to the SSD (paging), which causes hitches.' `
            'Close browsers, launchers and other apps while gaming. If it happens often, more RAM helps.'
    }
    if ((Count-Samples { param($s) $s.Disk -ge 90 }) -ge $need) {
        $who = ''; if ($last.BgName) { $who = " Busiest background app: $($last.BgName)." }
        Add-LiveProblem 'disk-busy' 'warn' 'Drive at 100% usage' `
            ("Something is reading or writing heavily (game asset streaming, Windows Update, a virus scan or a download).$who") `
            'Pause downloads and updates while gaming, and keep your games on an SSD.'
    }
    if ($last.BgPct -ge 15 -and (Count-Samples { param($s) $s.BgPct -ge 15 }) -ge $need) {
        $base = ([string]$last.BgName).ToLower()
        $hint = 'Close it while gaming.'
        if ($BgHints.ContainsKey($base)) { $hint = $BgHints[$base] }
        Add-LiveProblem "bg-$base" 'warn' ("'{0}' uses {1:0}% CPU in the background" -f $last.BgName, $last.BgPct) `
            'A background program is taking CPU time away from the game.' $hint
    }
    $first = $LiveSamples[0]
    $stut = [int]$last.Stut - [int]$first.Stut
    if ($fpsKnown -and $stut -ge 3) {
        $cause = 'Short freezes usually come from shader compilation or asset streaming in the game (common right after a game or driver update).'
        $fix = 'Play a few minutes so shaders finish compiling, cap FPS slightly below what you normally reach for even frame pacing, and keep your GPU driver up to date.'
        if ($LiveProblems.ContainsKey('vram-full')) { $cause = 'Graphics memory is full, so textures are swapped in and out.'; $fix = 'Lower texture quality one step.' }
        elseif ($LiveProblems.ContainsKey('disk-busy')) { $cause = 'The drive is at 100%, so the game waits for data.'; $fix = 'Stop downloads/updates and keep games on an SSD.' }
        elseif ($LiveProblems.ContainsKey('ram-full')) { $cause = 'System memory is full, so Windows pages to the SSD.'; $fix = 'Close background apps.' }
        elseif ($LiveProblems.ContainsKey('cpu-bound')) { $cause = 'The CPU is maxed out, so some frames take much longer.'; $fix = 'Lower CPU-heavy settings and close background apps.' }
        Add-LiveProblem 'stutter' 'warn' ("Stutter detected ({0} big frame-time spikes in a few seconds)" -f $stut) $cause $fix
    }
    if ($fpsKnown -and (Count-Samples { param($s) $s.Fps -gt 30 -and $s.Low -gt 0 -and $s.Low -lt $s.Fps * 0.5 }) -ge $need) {
        Add-LiveProblem 'low-1pct' 'info' 'Uneven frame times (1% lows far below the average)' `
            ("Average {0:0} FPS, but the slowest frames run at only {1:0} FPS - this feels like micro-stutter." -f $last.Fps, $last.Low) `
            'Cap your FPS a little below your average (in-game or in the NVIDIA / AMD control panel) for smoother, more consistent frames.'
    }
    if ((Count-Samples { param($s) ($s.Ping -gt 80) -or ($s.Loss -ge 2) }) -ge $need) {
        Add-LiveProblem 'ping' 'warn' ("Internet lag: {0:0} ms ping, {1:0}% packet loss" -f $last.Ping, $last.Loss) `
            'Your connection to the internet is unstable or slow (Wi-Fi, other devices downloading or streaming, router).' `
            'Use a LAN cable instead of Wi-Fi, pause downloads and streams on other devices, restart the router. The Network & Ping optimizations help on the Windows side.'
    }
    if ((Count-Samples { param($s) $s.Perf -gt 0 -and $s.Perf -lt 70 -and $s.Cpu -ge 40 }) -ge $need) {
        Add-LiveProblem 'cpu-clock' 'warn' 'CPU is running below its normal clock speed' `
            'Power saving or a temperature / power limit is holding the CPU back.' `
            'Use the Ultimate Performance power plan, check the CPU cooler and temperatures, and plug in the charger on laptops.'
    }
    if ((Count-Samples { param($s) $s.Power }) -ge 7 -and (Count-Samples { param($s) $s.Gpu -ge 95 }) -ge 7) {
        Add-LiveProblem 'gpu-power' 'info' 'Graphics card is at its power limit' `
            'The GPU is using all the power it is allowed to - normal under full load, it simply cannot boost higher.' `
            'Nothing is broken. For more headroom, lower settings or use DLSS / FSR.'
    }
}

function Update-Live {
    $key = $Sync.GameKey
    if (-not $LiveAuto.IsChecked) { $key = $null }
    if ($key -and -not $LiveSession) { Start-LiveSession $key }
    elseif ((-not $key) -and $LiveSession) { End-LiveSession; return }
    elseif ($key -and $LiveSession -and $Sync.Watch[$key] -and $Sync.Watch[$key].Exe -ne $LiveSession.Exe) { End-LiveSession; Start-LiveSession $key }
    if (-not $LiveSession) { return }
    $s = $LiveSession
    $fps = [double]$Sync.Fps; $low = [double]$Sync.Low1
    if ($Sync.PmState -eq 'missing') { $LvFps.Text = 'n/a'; $LvFpsSub.Text = 'FPS counter not available' }
    elseif ($fps -gt 0) { $LvFps.Text = '{0:0}' -f $fps; $LvFpsSub.Text = 'frames per second' }
    else { $LvFps.Text = '-'; $LvFpsSub.Text = 'waiting for frames...' }
    if ($low -gt 0) { $LvLow.Text = '{0:0}' -f $low } else { $LvLow.Text = '-' }
    if ($Sync.FrameMs -gt 0) { $LvFt.Text = '{0:0.0} ms' -f $Sync.FrameMs } else { $LvFt.Text = '-' }
    if ([double]$Sync.InputLat -gt 0) {
        $LvFtSub.Text = 'input to display {0:0} ms' -f $Sync.InputLat
        $script:LastLat = [double]$Sync.InputLat; $s.LatSum += [double]$Sync.InputLat; $s.LatN++
    } else { $LvFtSub.Text = 'time per frame' }
    $LvStut.Text = "$([int]$Sync.StutterTotal)"
    if ([double]$Sync.Gpu -ge 0) { $LvGpu.Text = '{0:0}%' -f $Sync.Gpu; $LvGpuSub.Text = '{0:0} {1}C' -f $Sync.GpuTemp, [char]176 } else { $LvGpu.Text = 'n/a'; $LvGpuSub.Text = '' }
    $LvCpu.Text = '{0:0}%' -f $Sync.Cpu; $LvCpuSub.Text = 'busiest core {0:0}%' -f $Sync.CoreMax
    if ([double]$Sync.VramTotal -gt 0) { $LvMem.Text = '{0:0.0} GB' -f $Sync.VramUsed; $LvMemSub.Text = 'VRAM of {0:0} GB  |  RAM {1:0}%' -f $Sync.VramTotal, $Sync.Ram }
    else { $LvMem.Text = '{0:0}%' -f $Sync.Ram; $LvMemSub.Text = 'RAM in use' }
    if ([double]$Sync.PingAvg -ge 0) { $LvPing.Text = '{0:0} ms' -f $Sync.PingAvg; $LvPingSub.Text = 'loss {0:0}%  |  max {1:0} ms' -f $Sync.Loss, $Sync.PingMax } else { $LvPing.Text = '-'; $LvPingSub.Text = 'measuring...' }
    if ($Sync.BgTop) { $LiveBg.Text = [string]$Sync.BgTop } else { $LiveBg.Text = 'Measuring...' }
    Draw-LiveGraph
    if ($fps -gt 0) { $s.FpsSum += $fps; $s.FpsN++ }
    if ($low -gt 0) { $s.LowSum += $low; $s.LowN++ }
    if ([double]$Sync.Gpu -ge 0) { $s.GpuSum += [double]$Sync.Gpu }
    $s.CpuSum += [double]$Sync.Cpu; $s.N++
    if ([double]$Sync.GpuTemp -gt $s.TempMax) { $s.TempMax = [double]$Sync.GpuTemp }
    [void]$LiveSamples.Add(@{
        Cpu = [double]$Sync.Cpu; Core = [double]$Sync.CoreMax; Perf = [double]$Sync.CpuPerf; Gpu = [double]$Sync.Gpu; Temp = [double]$Sync.GpuTemp
        Vram = [double]$Sync.VramUsed; VramTot = [double]$Sync.VramTotal; Ram = [double]$Sync.Ram; Disk = [double]$Sync.Disk
        Fps = $fps; Low = $low; Ping = [double]$Sync.PingAvg; Loss = [double]$Sync.Loss; BgName = [string]$Sync.BgName; BgPct = [double]$Sync.BgPct
        Thermal = [bool]$Sync.Thermal; Power = [bool]$Sync.PowerCap; Stut = [int]$Sync.StutterTotal })
    while ($LiveSamples.Count -gt 8) { $LiveSamples.RemoveAt(0) }
    $script:LiveTick++
    if ((Get-Date) - $s.Start -gt [TimeSpan]::FromSeconds(20) -and ($LiveTick % 2 -eq 0)) {
        try { Test-LiveRules } catch { Write-Log "Live rule error: $_" }
    }
}

# ------------------------------------------------------------------ Process Reducer
$script:ProcBaseline = 0
$script:ProcRows = @()
$script:ProcPresetIds = @('svchost-group', 'extra-services', 'print-spooler', 'sysmain', 'telemetry', 'telemetry-tasks', 'widgets', 'copilot',
    'cortana', 'recall', 'tips', 'bg-apps', 'edge-bg', 'onedrive-start', 'wer', 'nvidia-tel')
$script:ProcProtected = @('powershell', 'pwsh', 'presentmon', 'nvidia-smi', 'explorer', 'dwm', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'smss',
    'svchost', 'fontdrvhost', 'sihost', 'ctfmon', 'audiodg', 'conhost', 'taskhostw', 'runtimebroker', 'searchhost', 'searchapp', 'startmenuexperiencehost',
    'shellexperiencehost', 'textinputhost', 'msmpeng', 'nissrv', 'mpdefendercoreservice', 'securityhealthservice', 'securityhealthsystray', 'smartscreen',
    'msedgewebview2', 'applicationframehost', 'systemsettings', 'lockapp', 'dllhost', 'wmiprvse', 'spoolsv', 'nvdisplay.container', 'nvcontainer',
    'vgc', 'vgtray', 'easyanticheat', 'easyanticheat_eos', 'beservice', 'faceit', 'faceitservice', 'faceitclient', 'steamservice', 'wudfhost', 'dashost',
    'lsaiso', 'memcompression', 'memory compression', 'registry', 'system', 'idle', 'secure system', 'taskmgr', 'mmc', 'cmd', 'windowsterminal',
    'openconsole', 'silvan boost', 'rundll32', 'sppsvc', 'msiexec', 'trustedinstaller', 'tiworker')
$script:ProcProtectedPaths = @('\NVIDIA Corporation\', '\Realtek\', '\Intel\', '\AMD\', '\ATI Technologies\', '\Windows Defender\', '\DriverStore\',
    '\Microsoft\Edge\Application\msedgewebview2', '\Common Files\', '\EasyAntiCheat', '\BattlEye', '\Riot Vanguard\', '\FACEIT')
$script:ProcCloseRec = @{
    'onedrive' = 'Cloud sync - can run later'; 'teams' = 'Teams chat'; 'ms-teams' = 'Teams chat'; 'msteams' = 'Teams chat'
    'widgets' = 'Windows Widgets feed'; 'widgetservice' = 'Windows Widgets feed'; 'phoneexperiencehost' = 'Phone Link'; 'yourphone' = 'Phone Link'
    'copilot' = 'Copilot app'; 'cortana' = 'Cortana'; 'googleupdate' = 'Google updater'; 'googlecrashhandler' = 'Google crash reporter'
    'googlecrashhandler64' = 'Google crash reporter'; 'microsoftedgeupdate' = 'Edge updater'; 'adobearm' = 'Adobe updater'; 'acrotray' = 'Adobe Acrobat tray'
    'ccxprocess' = 'Adobe Creative Cloud helper'; 'adobecollabsync' = 'Adobe sync'; 'coresync' = 'Adobe sync'; 'creative cloud' = 'Adobe Creative Cloud'
    'adobeupdateservice' = 'Adobe updater'; 'jusched' = 'Java updater'; 'skype' = 'Skype'; 'crossdeviceresume' = 'Cross-device resume'
    'gamebar' = 'Xbox Game Bar'; 'gamebarftserver' = 'Xbox Game Bar'; 'msedge' = 'Microsoft Edge (background)'
}
$script:ProcCloseOpt = @{
    'chrome' = 'Browser'; 'firefox' = 'Browser'; 'opera' = 'Browser'; 'brave' = 'Browser'; 'discord' = 'Discord (voice chat)'; 'spotify' = 'Music'
    'steam' = 'Steam - needed for Steam games'; 'epicgameslauncher' = 'Epic launcher - needed for Epic games'; 'eadesktop' = 'EA app'
    'battle.net' = 'Battle.net'; 'riotclientservices' = 'Riot Client - needed for Riot games'; 'overwolf' = 'Overwolf overlays'
    'lghub' = 'Logitech G HUB (mouse macros)'; 'icue' = 'Corsair iCUE (RGB)'; 'obs64' = 'OBS'; 'wallpaper64' = 'Wallpaper Engine'
}

function Get-ProcStats {
    $p = @(Get-Process -ErrorAction SilentlyContinue)
    @{
        Procs   = $p.Count
        Threads = [int](($p | ForEach-Object { $_.Threads.Count } | Measure-Object -Sum).Sum)
        Svc     = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }).Count
        Svchost = @($p | Where-Object { $_.ProcessName -eq 'svchost' }).Count
    }
}

function Update-ProcStats {
    $s = Get-ProcStats
    $PcProc.Text = "$($s.Procs)"
    if ($ProcBaseline -gt 0) {
        $d = $ProcBaseline - $s.Procs
        if ($d -gt 0) { $PcProcSub.Text = "$d fewer than at start ($ProcBaseline)" } else { $PcProcSub.Text = "at start: $ProcBaseline" }
    }
    $PcSvc.Text = "$($s.Svc)"
    $PcSvch.Text = "$($s.Svchost)"
    $grouped = $TweakById['svchost-group'].Active
    if ($s.Svchost -gt 40 -and -not $grouped) { $PcSvchSub.Text = 'can be grouped - see Reduce' }
    elseif ($grouped -and $s.Svchost -gt 40) { $PcSvchSub.Text = 'grouped after next restart' }
    else { $PcSvchSub.Text = 'service host processes' }
    $PcThr.Text = '{0:N0}' -f $s.Threads
    $s
}

function Test-ProcProtected($name, $path) {
    $n = $name.ToLower()
    if ($ProcProtected -contains $n) { return $true }
    if ($Sync.Watch -and $Sync.Watch.ContainsKey($n)) { return $true }
    if (-not $path) { return $true }
    if ($path.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    foreach ($pp in $ProcProtectedPaths) { if ($path.IndexOf($pp, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }
    return $false
}

function Build-ProcList {
    $ProcList.Children.Clear()
    $rows = New-Object System.Collections.ArrayList
    foreach ($g in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID } | Group-Object ProcessName)) {
        $first = $g.Group[0]
        $path = $null; try { $path = $first.Path } catch { }
        if (Test-ProcProtected $g.Name $path) { continue }
        $n = $g.Name.ToLower()
        $desc = $null; try { $desc = $first.Description } catch { }
        $rec = $ProcCloseRec.ContainsKey($n)
        if ($rec) { $desc = $ProcCloseRec[$n] } elseif ($ProcCloseOpt.ContainsKey($n)) { $desc = $ProcCloseOpt[$n] }
        if (-not $desc) { $desc = $g.Name }
        $ram = ($g.Group | Measure-Object WorkingSet64 -Sum).Sum / 1MB
        [void]$rows.Add(@{ Name = $g.Name; Key = $n; Count = $g.Count; Ram = $ram; Desc = $desc; Rec = $rec; Toggle = $null })
    }
    $script:ProcRows = @($rows | Sort-Object @{ Expression = { if ($_.Rec) { 0 } else { 1 } } }, @{ Expression = { $_.Ram }; Descending = $true } | Select-Object -First 45)
    foreach ($r in $ProcRows) {
        $chip = '<Border CornerRadius="6" Padding="7,1" Margin="8,0,0,0" Background="#1A2440" VerticalAlignment="Center"><TextBlock Text="Optional" FontSize="10.5" Foreground="#A9B3CC"/></Border>'
        if ($r.Rec) { $chip = '<Border CornerRadius="6" Padding="7,1" Margin="8,0,0,0" Background="#1A2ED47A" VerticalAlignment="Center"><TextBlock Text="Recommended" FontSize="10.5" Foreground="#5BE39A"/></Border>' }
        $cnt = ''; if ($r.Count -gt 1) { $cnt = "  x$($r.Count)" }
        $xml = @"
<Border $NS BorderBrush="#1A2440" BorderThickness="0,1,0,0" Padding="0,9">
  <DockPanel>
    <CheckBox x:Name="Tg" DockPanel.Dock="Right" Style="{DynamicResource Toggle}" VerticalAlignment="Center" Margin="10,0,0,0"/>
    <TextBlock DockPanel.Dock="Right" Text="$('{0:N0} MB' -f $r.Ram)" FontSize="12" Foreground="#9AA5BF" VerticalAlignment="Center" Width="70" TextAlignment="Right"/>
    <StackPanel VerticalAlignment="Center">
      <StackPanel Orientation="Horizontal">
        <TextBlock Text="$(X ($r.Name + $cnt))" FontSize="13.5" FontWeight="SemiBold"/>
        $chip
      </StackPanel>
      <TextBlock Text="$(X $r.Desc)" FontSize="12" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis" Margin="0,2,0,0"/>
    </StackPanel>
  </DockPanel>
</Border>
"@
        $row = [System.Windows.Markup.XamlReader]::Parse($xml)
        $r.Toggle = $row.FindName('Tg')
        $r.Toggle.IsChecked = $r.Rec
        $r.Toggle.Add_Click({ Update-ProcCount })
        [void]$ProcList.Children.Add($row)
    }
    if ($ProcRows.Count -eq 0) {
        [void]$ProcList.Children.Add([System.Windows.Markup.XamlReader]::Parse("<TextBlock $NS Text=`"No extra apps running - nice and clean.`" Foreground=`"#9AA5BF`" Margin=`"0,8,0,0`"/>"))
    }
    Update-ProcCount
}

function Update-ProcCount {
    $n = @($ProcRows | Where-Object { $_.Toggle -and $_.Toggle.IsChecked }).Count
    $BtnProcClose.Content = "Close selected ($n)"
    $BtnProcClose.IsEnabled = ($n -gt 0)
}

function Close-SelectedProcs([switch]$NoConfirm) {
    $sel = @($ProcRows | Where-Object { $_.Toggle -and $_.Toggle.IsChecked })
    if ($sel.Count -eq 0) { return 0 }
    if (-not $NoConfirm) {
        $names = ($sel | ForEach-Object { ' - ' + $_.Name }) -join "`n"
        $r = Show-Msg "Close these apps now?`n`n$names`n`nUnsaved work in them will be lost. They start again normally the next time you open them." 'Close apps' 'YesNo' 'Question'
        if ([string]$r -ne 'Yes') { return 0 }
    }
    $closed = 0
    foreach ($s in $sel) {
        foreach ($p in @(Get-Process -Name $s.Name -ErrorAction SilentlyContinue)) {
            try { $p.Kill(); $closed++ } catch { }
        }
        Write-Log "Process Reducer: closed $($s.Name)"
    }
    $closed
}

# Startup apps (same switches Task Manager uses - fully reversible)
function Get-StartupEntries {
    $list = New-Object System.Collections.ArrayList
    $sa = 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
    $srcs = @(
        @{ Run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Appr = "HKCU:\$sa\Run" },
        @{ Run = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Appr = "HKLM:\$sa\Run" },
        @{ Run = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Appr = "HKLM:\$sa\Run32" }
    )
    foreach ($src in $srcs) {
        if (-not (Test-Path -LiteralPath $src.Run)) { continue }
        $k = Get-Item -LiteralPath $src.Run
        foreach ($n in $k.GetValueNames()) {
            if (-not $n) { continue }
            [void]$list.Add(@{ Name = $n; Cmd = [string]$k.GetValue($n); Appr = $src.Appr; Toggle = $null })
        }
    }
    $folders = @(
        @{ Dir = [Environment]::GetFolderPath('Startup'); Appr = "HKCU:\$sa\StartupFolder" },
        @{ Dir = [Environment]::GetFolderPath('CommonStartup'); Appr = "HKLM:\$sa\StartupFolder" }
    )
    foreach ($f in $folders) {
        if (-not $f.Dir -or -not (Test-Path -LiteralPath $f.Dir)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $f.Dir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            [void]$list.Add(@{ Name = $file.Name; Cmd = $file.FullName; Appr = $f.Appr; Toggle = $null })
        }
    }
    $list
}

function Test-StartupEnabled($e) {
    $b = Get-RegValue $e.Appr $e.Name
    if ($b -is [byte[]] -and $b.Length -gt 0) { return (($b[0] -band 1) -eq 0) }
    return $true
}

function Set-StartupEnabled($e, [bool]$on) {
    if (-not (Test-Path -LiteralPath $e.Appr)) { New-Item -Path $e.Appr -Force | Out-Null }
    if ($on) { [byte[]]$v = @(2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) }
    else { [byte[]]$v = @(3, 0, 0, 0) + [BitConverter]::GetBytes([DateTime]::Now.ToFileTime()) }
    New-ItemProperty -LiteralPath $e.Appr -Name $e.Name -Value $v -PropertyType Binary -Force | Out-Null
    Write-Log ("Startup app {0}: {1}" -f $e.Name, $(if ($on) { 'enabled' } else { 'disabled' }))
}

function Build-StartList {
    $StartList.Children.Clear()
    $script:StartEntries = @(Get-StartupEntries)
    $i = 0
    foreach ($e in $StartEntries) {
        $exe = ($e.Cmd -replace '^"([^"]+)".*$', '$1') -replace '\s+-.*$', ''
        $xml = @"
<Border $NS BorderBrush="#1A2440" BorderThickness="0,1,0,0" Padding="0,9">
  <DockPanel>
    <CheckBox x:Name="Tg" DockPanel.Dock="Right" Style="{DynamicResource Toggle}" VerticalAlignment="Center" Margin="10,0,0,0"/>
    <StackPanel VerticalAlignment="Center">
      <TextBlock Text="$(X $e.Name)" FontSize="13.5" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
      <TextBlock Text="$(X $exe)" FontSize="11.5" Foreground="#7F8BA6" TextTrimming="CharacterEllipsis" Margin="0,2,0,0"/>
    </StackPanel>
  </DockPanel>
</Border>
"@
        $row = [System.Windows.Markup.XamlReader]::Parse($xml)
        $row.ToolTip = $e.Cmd
        $tg = $row.FindName('Tg')
        $tg.IsChecked = (Test-StartupEnabled $e)
        $tg.Tag = $i
        $tg.Add_Click({ param($s, $ev) try { Set-StartupEnabled $StartEntries[[int]$s.Tag] ([bool]$s.IsChecked); Set-Status 'Startup app changed - takes effect at next sign-in.' } catch { Write-Log "Startup toggle error: $_" } })
        $e.Toggle = $tg
        [void]$StartList.Children.Add($row)
        $i++
    }
    $on = @($StartEntries | Where-Object { $_.Toggle.IsChecked }).Count
    $StartSub.Text = "$on of $($StartEntries.Count) apps start with Windows. Switch off what you do not need right after boot - fewer processes every time."
    if ($StartEntries.Count -eq 0) { $StartSub.Text = 'No startup apps found.' }
}

function Load-ProcPage {
    Show-Overlay 'Counting processes...'
    try {
        [void](Update-ProcStats)
        Build-ProcList
        Build-StartList
        $ProcSub.Text = 'See what is running and push the number of processes down as far as is safe.'
    } catch { Write-Log "Process page error: $_" }
    Hide-Overlay
}

function Invoke-ReduceProcesses {
    $before = (Get-ProcStats).Procs
    $tw = @($ProcPresetIds | ForEach-Object { $TweakById[$_] } | Where-Object { $_ -and -not $_.Active -and (Test-Suitable $_) })
    $apps = @($ProcRows | Where-Object { $_.Toggle -and $_.Toggle.IsChecked })
    if ($tw.Count -eq 0 -and $apps.Count -eq 0) {
        Show-Msg "Everything is already reduced. Switch on more apps in the list or turn off startup apps to go even lower." 'Process Reducer' | Out-Null
        return
    }
    $lines = New-Object System.Collections.ArrayList
    if ($tw.Count -gt 0) { [void]$lines.Add("- $($tw.Count) optimizations that remove background processes:`n   " + (($tw | ForEach-Object { $_.Name }) -join "`n   ")) }
    if ($apps.Count -gt 0) { [void]$lines.Add("- Close $($apps.Count) app(s): " + (($apps | ForEach-Object { $_.Name }) -join ', ')) }
    $r = Show-Msg ("Reduce processes now?`n`n" + ($lines -join "`n") + "`n`nEverything except closed apps can be undone. Unsaved work in closed apps is lost.") 'Process Reducer' 'YesNo' 'Question'
    if ([string]$r -ne 'Yes') { return }
    if ($tw.Count -gt 0 -and -not (Ensure-RestorePoint)) { return }
    $i = 0
    foreach ($t in $tw) {
        $i++
        Show-Overlay ("Reducing processes: {0} of {1}`n{2}" -f $i, $tw.Count, $t.Name)
        [void](Set-TweakState $t $true -Quiet)
    }
    Show-Overlay 'Closing background apps...'
    $closed = Close-SelectedProcs -NoConfirm
    Start-Sleep -Seconds 2
    Hide-Overlay
    $now = (Update-ProcStats).Procs
    Build-ProcList
    $msg = "Processes: $before -> $now (" + ($before - $now) + ' fewer right now).'
    if ($TweakById['svchost-group'].Active -or $RebootPill.Visibility -eq 'Visible') {
        $msg += "`n`nAfter a restart the number drops further: disabled services stay off and Windows groups its services into far fewer svchost.exe processes."
    }
    $msg += "`n`nTip: switch off unneeded startup apps on the right so they do not come back after the next boot."
    Write-Log "Process Reducer: $before -> $now processes, $closed process(es) closed."
    Set-Status "Process Reducer: $before -> $now processes"
    Show-Msg $msg 'Process Reducer' | Out-Null
}

# ------------------------------------------------------------------ shared: apply a list of tweaks
function Invoke-TweakList([string]$title, $ids, [string]$intro) {
    $tw = @($ids | ForEach-Object { $TweakById[$_] } | Where-Object { $_ -and -not $_.Action -and $_.Risk -ne 'Advanced' -and -not $_.Active -and (Test-Suitable $_) })
    if ($tw.Count -eq 0) { return @{ Run = $true; Applied = 0; Failed = @() } }
    $r = Show-Msg ("$intro`n`n" + (($tw | ForEach-Object { ' - ' + $_.Name }) -join "`n") + "`n`nEverything can be undone.") $title 'YesNo' 'Question'
    if ([string]$r -ne 'Yes') { return @{ Run = $false } }
    if (-not (Ensure-RestorePoint)) { return @{ Run = $false } }
    $fail = New-Object System.Collections.ArrayList; $i = 0
    foreach ($t in $tw) {
        $i++
        Show-Overlay ("{0}: {1} of {2}`n{3}" -f $title, $i, $tw.Count, $t.Name)
        if (-not (Set-TweakState $t $true -Quiet)) { [void]$fail.Add($t.Name) }
    }
    Hide-Overlay
    @{ Run = $true; Applied = $tw.Count - $fail.Count; Failed = @($fail) }
}

function Add-FeatRows($panel, $ids) {
    $panel.Children.Clear()
    foreach ($id in $ids) {
        $t = $TweakById[$id]; if (-not $t) { continue }
        $row = New-FeatRow $t
        if ($t.Risk -ne 'Safe') {
            $sp = $row.Child.Children[1]
            $tb = New-Object System.Windows.Controls.TextBlock
            $tb.Text = $(if ($t.Risk -eq 'Advanced') { 'Advanced - asks before applying' } else { 'Moderate - small trade-off' })
            $tb.FontSize = 11; $tb.Margin = [System.Windows.Thickness]::new(0, 2, 0, 0)
            $tb.Foreground = Get-Brush $(if ($t.Risk -eq 'Advanced') { '#F87171' } else { '#FBBF24' })
            [void]$sp.Children.Add($tb)
        }
        [void]$panel.Children.Add($row)
        Update-TweakUI $t
    }
}

# ------------------------------------------------------------------ Ping Booster
$script:PingIds = @('net-throttle', 'nagle', 'nic-power', 'nic-eee', 'nic-lso', 'nic-rsc', 'nic-rss', 'nic-buffers', 'wifi-roam', 'qos-games', 'delivery-opt', 'do-limit', 'nic-flowctl', 'int-mod', 'dns-cf')
$script:PingBoostIds = @('net-throttle', 'nagle', 'nic-power', 'nic-eee', 'nic-lso', 'nic-rsc', 'nic-rss', 'nic-buffers', 'wifi-roam', 'qos-games', 'delivery-opt', 'do-limit')
$script:PingRes = @{}
$script:PingRowsBuilt = $false
$script:Regions = @(
    @('Frankfurt', 'eu-central-1'), @('Paris', 'eu-west-3'), @('London', 'eu-west-2'), @('Ireland', 'eu-west-1'),
    @('Stockholm', 'eu-north-1'), @('Milan', 'eu-south-1'), @('US East (Virginia)', 'us-east-1'), @('US West (Oregon)', 'us-west-2'))
$script:DnsChoices = @(
    @('Cloudflare', '1.1.1.1', '1.0.0.1'), @('Google', '8.8.8.8', '8.8.4.4'), @('Quad9', '9.9.9.9', '149.112.112.112'), @('OpenDNS', '208.67.222.222', '208.67.220.220'))
$script:DnsResults = @()

function Get-ConnInfo {
    $ci = @{ Gateway = $null; Name = 'No connection'; Wifi = $false; Speed = ''; Signal = -1; Band = ''; Radio = ''; Index = 0 }
    $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
    if (-not $r) { return $ci }
    $ci.Gateway = [string]$r.NextHop; $ci.Index = [int]$r.ifIndex
    $n = Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue
    if ($n) {
        $ci.Name = [string]$n.InterfaceDescription; $ci.Speed = [string]$n.LinkSpeed
        $ci.Wifi = ([int]$n.NdisPhysicalMedium -eq 9) -or ($ci.Name -match 'Wi-?Fi|Wireless|WLAN|802\.11')
    }
    if ($ci.Wifi) {
        $o = (netsh wlan show interfaces) | Out-String
        if ($o -match '(?m)^\s*Signal\s*:\s*(\d+)\s*%') { $ci.Signal = [int]$Matches[1] }
        if ($o -match '(?m)^\s*Band\s*:\s*(.+?)\s*$') { $ci.Band = $Matches[1] }
        elseif ($o -match '(?m)^\s*(Channel|Kanal)\s*:\s*(\d+)') { $ci.Band = $(if ([int]$Matches[2] -le 14) { '2.4 GHz' } else { '5 GHz' }) }
        if ($o -match '(?m)^\s*(Radio type|Funktyp)\s*:\s*(.+?)\s*$') { $ci.Radio = $Matches[2] }
    }
    $ci
}

function Measure-Pings([string]$target, [int]$n, [int]$gapMs) {
    $p = New-Object System.Net.NetworkInformation.Ping
    $res = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $n; $i++) {
        $v = -1.0
        try { $r = $p.Send($target, 1000); if ($r.Status -eq 'Success') { $v = [double]$r.RoundtripTime } } catch { }
        [void]$res.Add($v)
        Flush-UI
        if ($gapMs -gt 0) { Start-Sleep -Milliseconds $gapMs }
    }
    , ([double[]]$res.ToArray())
}

function Get-PingStats($arr) {
    $arr = @($arr)
    $st = @{ Avg = -1.0; Jit = 0.0; Loss = 0.0; Min = -1.0; Max = -1.0 }
    $ok = @($arr | Where-Object { $_ -ge 0 })
    if ($arr.Count -gt 0) { $st.Loss = ($arr.Count - $ok.Count) / $arr.Count * 100 }
    if ($ok.Count -gt 0) {
        $m = $ok | Measure-Object -Average -Minimum -Maximum
        $st.Avg = [double]$m.Average; $st.Min = [double]$m.Minimum; $st.Max = [double]$m.Maximum
        if ($ok.Count -gt 1) {
            $d = 0.0; for ($i = 1; $i -lt $ok.Count; $i++) { $d += [Math]::Abs($ok[$i] - $ok[$i - 1]) }
            $st.Jit = $d / ($ok.Count - 1)
        }
    }
    $st
}

function Measure-Tcp([System.Net.IPAddress]$ip, [int]$timeout) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $task = $c.ConnectAsync($ip, 443)
        if ($task.Wait($timeout) -and $c.Connected) { return $sw.Elapsed.TotalMilliseconds }
    } catch { } finally { $c.Close() }
    -1.0
}

function Test-Regions {
    $out = New-Object System.Collections.ArrayList
    foreach ($rg in $Regions) {
        Show-Overlay "Testing game server regions...`n$($rg[0])"
        $best = -1.0
        try {
            $ip = [System.Net.Dns]::GetHostAddresses("dynamodb.$($rg[1]).amazonaws.com") | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
            if ($ip) {
                for ($k = 0; $k -lt 3; $k++) {
                    $v = Measure-Tcp $ip 1500
                    if ($v -lt 0) { break }
                    if ($best -lt 0 -or $v -lt $best) { $best = $v }
                    Flush-UI
                }
            }
        } catch { }
        [void]$out.Add(@{ Name = $rg[0]; Ms = $best })
    }
    @($out | Sort-Object @{ Expression = { if ($_.Ms -lt 0) { 99999 } else { $_.Ms } } })
}

function Test-Bufferbloat([double]$idleAvg) {
    $dl = [hashtable]::Synchronized(@{ Run = $true })
    $pool = [runspacefactory]::CreateRunspacePool(1, 3); $pool.Open()
    $jobs = @()
    for ($k = 0; $k -lt 3; $k++) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript({
            param($dl, $k)
            $dl["b$k"] = [long]0
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $req = [Net.HttpWebRequest]::Create('https://speed.cloudflare.com/__down?bytes=250000000')
                $req.Timeout = 15000; $req.UserAgent = 'SilvanBoost'
                $dl["r$k"] = $req
                $resp = $req.GetResponse(); $s = $resp.GetResponseStream()
                $buf = New-Object byte[] 65536; $tot = [long]0
                while ($dl.Run) {
                    $n = $s.Read($buf, 0, $buf.Length)
                    if ($n -le 0) { break }
                    $tot += $n; $dl["b$k"] = $tot
                }
                $s.Close(); $resp.Close()
            } catch { if ($dl.Run) { $dl.Err = $_.Exception.Message } }
        }).AddArgument($dl).AddArgument($k)
        $jobs += @{ PS = $ps; H = $ps.BeginInvoke() }
    }
    $bytes = { [long]$dl['b0'] + [long]$dl['b1'] + [long]$dl['b2'] }
    for ($w = 0; $w -lt 15; $w++) { Start-Sleep -Milliseconds 100; Flush-UI }
    $b0 = & $bytes
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $loaded = Measure-Pings '1.1.1.1' 20 250
    $sec = $sw.Elapsed.TotalSeconds
    $b1 = & $bytes
    $dl.Run = $false
    foreach ($k in 0..2) { try { if ($dl["r$k"]) { $dl["r$k"].Abort() } } catch { } }
    foreach ($j in $jobs) { try { [void]$j.H.AsyncWaitHandle.WaitOne(2000) } catch { }; try { $j.PS.Dispose() } catch { } }
    try { $pool.Close() } catch { }
    $st = Get-PingStats $loaded
    $mbps = 0.0; if ($sec -gt 0) { $mbps = ($b1 - $b0) * 8 / $sec / 1e6 }
    @{ Loaded = $st; Mbps = $mbps; Err = $dl.Err; Bloat = $(if ($st.Avg -ge 0 -and $idleAvg -ge 0) { [Math]::Max(0, $st.Avg - $idleAvg) } else { -1.0 }) }
}

function Get-BloatGrade([double]$b) {
    if ($b -lt 0) { return '?' }
    if ($b -lt 5) { return 'A+' }; if ($b -lt 30) { return 'A' }; if ($b -lt 60) { return 'B' }
    if ($b -lt 200) { return 'C' }; if ($b -lt 400) { return 'D' }; 'F'
}

function Get-ActiveDns {
    $ci = $PingRes.Conn; if (-not $ci) { $ci = Get-ConnInfo }
    @((Get-DnsClientServerAddress -InterfaceIndex $ci.Index -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
}

function Measure-Dns([string]$server) {
    $doms = @('riotgames.com', 'epicgames.com', 'steampowered.com', 'discord.com', 'ea.com', 'battle.net', 'twitch.tv', 'youtube.com')
    $t = New-Object System.Collections.ArrayList
    foreach ($d in $doms) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try { $null = Resolve-DnsName -Name $d -Server $server -DnsOnly -NoHostsFile -QuickTimeout -Type A -ErrorAction Stop; [void]$t.Add($sw.Elapsed.TotalMilliseconds) }
        catch { [void]$t.Add(2000.0) }
        Flush-UI
    }
    $a = [double[]]$t.ToArray(); [Array]::Sort($a)
    $a[[int][Math]::Floor($a.Length / 2)]
}

function Test-DnsServers {
    $res = New-Object System.Collections.ArrayList
    $cur = @(Get-ActiveDns)
    $curIp = $null; if ($cur.Count -gt 0) { $curIp = [string]$cur[0] }
    $seen = @{}
    if ($curIp) {
        Show-Overlay "DNS benchmark...`nYour current DNS ($curIp)"
        $nm = 'Your current DNS'
        foreach ($c in $DnsChoices) { if ($c[1] -eq $curIp) { $nm = "$($c[0]) (current)" } }
        [void]$res.Add(@{ Name = $nm; Ip = $curIp; Ip2 = $null; Ms = (Measure-Dns $curIp); Current = $true })
        $seen[$curIp] = $true
    }
    foreach ($c in $DnsChoices) {
        if ($seen.ContainsKey($c[1])) { continue }
        Show-Overlay "DNS benchmark...`n$($c[0]) ($($c[1]))"
        [void]$res.Add(@{ Name = $c[0]; Ip = $c[1]; Ip2 = $c[2]; Ms = (Measure-Dns $c[1]); Current = $false })
    }
    $script:DnsResults = @($res | Sort-Object { $_.Ms })
}

function Set-DnsAll([string]$p, [string]$s) {
    $n = Get-UpNics
    if (-not $n) { throw 'No connected network adapter found.' }
    foreach ($a in $n) {
        $k = "dns_$($a.InterfaceGuid)"
        if (-not $State.misc.ContainsKey($k)) {
            $State.misc[$k] = [string](Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($a.InterfaceGuid)" 'NameServer')
        }
        $list = @($p); if ($s) { $list += $s }
        Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $list -ErrorAction Stop
    }
    Clear-DnsClientCache
    Save-State
    Write-Log "DNS set to $p $s"
    $t = $TweakById['dns-cf']; $t.Active = Test-Tweak $t; Update-TweakUI $t
}

function Reset-DnsAll {
    & $TweakById['dns-cf'].Revert
    Save-State
    Write-Log 'DNS reset to previous / automatic'
    $t = $TweakById['dns-cf']; $t.Active = Test-Tweak $t; Update-TweakUI $t
}

function Show-DnsResults {
    $DnsList.Children.Clear()
    if ($DnsResults.Count -eq 0) { return }
    $best = $DnsResults[0].Ms
    for ($i = 0; $i -lt $DnsResults.Count; $i++) {
        $d = $DnsResults[$i]
        $col = '#5BE39A'; if ($d.Ms -gt $best * 1.5 + 5) { $col = '#FBBF24' }; if ($d.Ms -ge 1500) { $col = '#F87171' }
        $ms = '{0:0} ms' -f $d.Ms; if ($d.Ms -ge 1500) { $ms = 'timeout' }
        $btn = '<Button x:Name="Use" DockPanel.Dock="Right" Style="{DynamicResource SmallBtn}" Content="Use" Margin="10,0,0,0" VerticalAlignment="Center"/>'
        if ($d.Current) { $btn = '<TextBlock DockPanel.Dock="Right" Text="in use" FontSize="11.5" Foreground="#7F8BA6" Margin="10,0,0,0" VerticalAlignment="Center"/>' }
        $xml = @"
<Border $NS BorderBrush="#1A2440" BorderThickness="0,1,0,0" Padding="0,8">
  <DockPanel>
    $btn
    <TextBlock DockPanel.Dock="Right" Text="$ms" FontSize="13" FontWeight="SemiBold" Foreground="$col" VerticalAlignment="Center"/>
    <StackPanel VerticalAlignment="Center">
      <TextBlock Text="$(X $d.Name)" FontSize="13" FontWeight="SemiBold"/>
      <TextBlock Text="$(X $d.Ip)" FontSize="11.5" Foreground="#7F8BA6"/>
    </StackPanel>
  </DockPanel>
</Border>
"@
        $row = [System.Windows.Markup.XamlReader]::Parse($xml)
        $u = $row.FindName('Use')
        if ($u) {
            $u.Tag = $i
            $u.Add_Click({ param($s, $e)
                    $d = $DnsResults[[int]$s.Tag]
                    try {
                        if (-not (Ensure-RestorePoint)) { return }
                        Set-DnsAll $d.Ip $d.Ip2
                        foreach ($x in $DnsResults) { $x.Current = ($x.Ip -eq $d.Ip) }
                        Show-DnsResults
                        Set-Status "DNS switched to $($d.Name)"
                    } catch { Show-Msg "Could not change DNS: $($_.Exception.Message)" 'Silvan Boost' 'OK' 'Error' | Out-Null }
                })
        }
        [void]$DnsList.Children.Add($row)
    }
}

function Show-Regions($list) {
    $RegionList.Children.Clear()
    $max = 1.0; foreach ($r in $list) { if ($r.Ms -gt $max) { $max = $r.Ms } }
    foreach ($r in $list) {
        $col = '#5BE39A'; if ($r.Ms -ge 35) { $col = '#FBBF24' }; if ($r.Ms -ge 80 -or $r.Ms -lt 0) { $col = '#F87171' }
        $ms = '{0:0} ms' -f $r.Ms; if ($r.Ms -lt 0) { $ms = 'blocked' }
        $w = 4; if ($r.Ms -gt 0) { $w = [Math]::Max(4, [int](160 * $r.Ms / $max)) }
        $xml = @"
<DockPanel $NS Margin="0,5,0,5">
  <TextBlock DockPanel.Dock="Right" Text="$ms" Width="62" TextAlignment="Right" FontSize="12.5" FontWeight="SemiBold" Foreground="$col"/>
  <Border DockPanel.Dock="Right" Width="166" Height="6" CornerRadius="3" Background="#1E2944" VerticalAlignment="Center">
    <Border Width="$w" HorizontalAlignment="Left" CornerRadius="3" Background="$col"/>
  </Border>
  <TextBlock Text="$(X $r.Name)" FontSize="12.5" VerticalAlignment="Center"/>
</DockPanel>
"@
        [void]$RegionList.Children.Add([System.Windows.Markup.XamlReader]::Parse($xml))
    }
}

function Update-ConnTile($ci) {
    if (-not $ci.Gateway) { $PgConn.Text = 'Offline'; $PgConnSub.Text = 'no internet route'; return }
    if ($ci.Wifi) {
        $PgConn.Text = 'Wi-Fi'
        $sub = @(); if ($ci.Signal -ge 0) { $sub += "signal $($ci.Signal)%" }; if ($ci.Band) { $sub += $ci.Band }; if ($ci.Speed) { $sub += $ci.Speed }
        $PgConnSub.Text = $sub -join '  |  '
        $PgConn.Foreground = Get-Brush '#FBBF24'
    } else {
        $PgConn.Text = 'Ethernet'; $PgConnSub.Text = "LAN cable  |  $($ci.Speed)"; $PgConn.Foreground = Get-Brush '#5BE39A'
    }
}

function Open-PingPage {
    try {
        $ci = Get-ConnInfo
        $PingRes.Conn = $ci
        $Sync.Gateway = $ci.Gateway
        Update-ConnTile $ci
        if (-not $PingRowsBuilt) { Add-FeatRows $PingTweakList $PingIds; $script:PingRowsBuilt = $true }
        Build-PingRecs
    } catch { Write-Log "Ping page error: $_" }
}

function Update-PingLive {
    $net = @($Sync.PgNet); $gw = @($Sync.PgGw)
    if ($net.Count -gt 0) {
        $last10 = Get-PingStats @($net | Select-Object -Last 10)
        $all = Get-PingStats $net
        if ($last10.Avg -ge 0) { $PgPing.Text = '{0:0} ms' -f $last10.Avg } else { $PgPing.Text = 'lost' }
        $PgPingSub.Text = 'to 1.1.1.1  |  best {0:0} ms' -f $all.Min
        $PgJit.Text = '{0:0.0} ms' -f (Get-PingStats @($net | Select-Object -Last 30)).Jit
        $PgLoss.Text = '{0:0.#}%' -f $all.Loss
        $PgLoss.Foreground = Get-Brush $(if ($all.Loss -ge 1) { '#F87171' } else { '#E8ECF5' })
    }
    if ($gw.Count -gt 0) {
        $g = Get-PingStats @($gw | Select-Object -Last 10)
        if ($g.Avg -ge 0) { $PgGw.Text = '{0:0} ms' -f $g.Avg; $PgGwSub.Text = 'jitter {0:0.0} ms' -f $g.Jit } else { $PgGw.Text = '-'; $PgGwSub.Text = 'router does not answer ping' }
    }
    $w = $PingGraph.ActualWidth; $h = $PingGraph.ActualHeight
    if ($w -le 0) { return }
    $top = 30.0
    foreach ($v in ($net + $gw)) { if ($v -gt $top / 1.2) { $top = $v * 1.2 } }
    $PingGraphMax.Text = '{0:0} ms' -f $top
    foreach ($pair in @(@($net, $PingLineNet), @($gw, $PingLineGw))) {
        $arr = @($pair[0]); $line = $pair[1]
        $pts = New-Object System.Windows.Media.PointCollection
        $step = $w / 59; $start = 60 - $arr.Count
        for ($i = 0; $i -lt $arr.Count; $i++) {
            $v = $arr[$i]; if ($v -lt 0) { $v = $top }
            $pts.Add([System.Windows.Point]::new(($start + $i) * $step, $h - ([Math]::Min($v, $top) / $top) * ($h - 4) - 2))
        }
        $line.Points = $pts
    }
}

function Invoke-PingTest {
    $res = $PingRes
    try {
        Show-Overlay 'Checking your connection...'
        $res.Conn = Get-ConnInfo
        $Sync.Gateway = $res.Conn.Gateway
        Update-ConnTile $res.Conn
        if (-not $res.Conn.Gateway) { Hide-Overlay; Show-Msg 'No internet connection found.' | Out-Null; return }
        Show-Overlay 'Measuring ping to your router and the internet...'
        $res.Gw = Get-PingStats (Measure-Pings $res.Conn.Gateway 10 100)
        $res.Net = Get-PingStats (Measure-Pings '1.1.1.1' 15 150)
        $res.Regions = Test-Regions
        Show-Regions $res.Regions
        Show-Overlay "Bufferbloat test - downloading at full speed for a few seconds`nand measuring how much your ping rises..."
        $res.Bb = Test-Bufferbloat $res.Net.Avg
        $g = Get-BloatGrade $res.Bb.Bloat
        $BbGrade.Text = $g
        $BbGrade.Foreground = Get-Brush $(switch -Regex ($g) { '^A' { '#5BE39A' } '^B' { '#A3E635' } '^C' { '#FBBF24' } '\?' { '#9AA5BF' } default { '#F87171' } })
        $BbIdle.Text = 'Idle ping: {0:0} ms' -f $res.Net.Avg
        if ($res.Bb.Loaded.Avg -ge 0) { $BbLoad.Text = 'Ping under load: {0:0} ms  (+{1:0} ms)' -f $res.Bb.Loaded.Avg, $res.Bb.Bloat } else { $BbLoad.Text = 'Ping under load: lost' }
        $BbSpeed.Text = 'Download during test: {0:0} Mbit/s' -f $res.Bb.Mbps
        if ($res.Bb.Err -and $res.Bb.Mbps -lt 1) { $BbNote.Text = 'The load test could not reach speed.cloudflare.com - result not reliable.' }
        else { $BbNote.Text = 'Bufferbloat = how much your ping rises while the connection is busy (someone streaming or downloading). It is the #1 cause of lag spikes at home.' }
        Test-DnsServers
        Show-DnsResults
        $res.Time = Get-Date
        Write-Log ("Ping test: router {0:0} ms, internet {1:0} ms jitter {2:0.0} loss {3:0}%, bufferbloat {4} (+{5:0} ms), best region {6}" -f $res.Gw.Avg, $res.Net.Avg, $res.Net.Jit, $res.Net.Loss, $g, $res.Bb.Bloat, $res.Regions[0].Name)
    } catch { Write-Log "Ping test error: $_" }
    Hide-Overlay
    Build-PingRecs
    Set-Status 'Ping test finished.'
}

function Build-PingRecs {
    $PingRecList.Children.Clear()
    $r = $PingRes
    $recs = New-Object System.Collections.ArrayList
    function PR2($s, $t, $x) { [void]$recs.Add(@{ S = $s; T = $t; X = $x }) }
    $ci = $r.Conn
    if ($ci) {
        if ($ci.Wifi) {
            PR2 'warn' 'You are playing over Wi-Fi' 'Wi-Fi adds ping spikes and packet loss, no matter how good the signal is. A LAN cable is the biggest ping upgrade there is. If the router is far away, use Powerline adapters or a mesh system with a wired backhaul.'
            if ($ci.Signal -ge 0 -and $ci.Signal -lt 70) { PR2 'warn' "Weak Wi-Fi signal ($($ci.Signal)%)" 'Move closer to the router, remove obstacles, or put the router higher up and in the open.' }
            if ($ci.Band -match '2\.4') { PR2 'warn' 'Connected on 2.4 GHz' 'The 2.4 GHz band is crowded and slow. Connect to the 5 GHz (or 6 GHz) network of your router - give it its own name in the router settings if needed.' }
        } elseif ($ci.Gateway) { PR2 'ok' 'Wired connection' "You are using a LAN cable ($($ci.Speed)) - the best way to play." }
    }
    if ($r.Gw) {
        if ($r.Gw.Loss -gt 0 -or $r.Gw.Jit -gt 5 -or $r.Gw.Avg -gt 10) {
            PR2 'warn' ('Unstable connection to your own router ({0:0} ms, jitter {1:0.0} ms, loss {2:0}%)' -f $r.Gw.Avg, $r.Gw.Jit, $r.Gw.Loss) 'The problem is inside your home network, not your internet provider: usually Wi-Fi interference, a bad cable or an overloaded router. Use a LAN cable and restart the router.'
        } elseif ($r.Gw.Avg -ge 0) { PR2 'ok' 'Home network is stable' ('Router answers in {0:0} ms with no loss.' -f $r.Gw.Avg) }
    }
    if ($r.Net) {
        if ($r.Net.Loss -gt 0) { PR2 'warn' ('Packet loss to the internet ({0:0}%)' -f $r.Net.Loss) 'Lost packets feel like teleporting enemies and missed shots. If your home network is fine, contact your internet provider.' }
        if ($r.Net.Jit -gt 8) { PR2 'warn' ('High jitter ({0:0.0} ms)' -f $r.Net.Jit) 'Your ping jumps around. Pause downloads, streams and cloud backups on all devices, and check the bufferbloat result.' }
    }
    if ($r.Bb -and $r.Bb.Bloat -ge 0) {
        $g = Get-BloatGrade $r.Bb.Bloat
        if ($g -match '^[CDF]') {
            PR2 'warn' ("Bufferbloat grade $g - ping rises by {0:0} ms when the line is busy" -f $r.Bb.Bloat) 'Turn on Smart Queue Management (SQM / QoS) in your router and set it to about 90% of your real speed. FRITZ!Box: Internet > Filter > Priorisierung > add this PC under "Echtzeitanwendungen". Also pause big downloads while you play.'
        } elseif ($g -ne '?') { PR2 'ok' "Bufferbloat grade $g" 'Your ping stays low even when the connection is busy.' }
    }
    if ($r.Regions -and $r.Regions.Count -gt 0 -and $r.Regions[0].Ms -ge 0) {
        $b = $r.Regions[0]
        PR2 'info' ('Closest game server region: {0} ({1:0} ms)' -f $b.Name, $b.Ms) "Many online games host their servers in these data centers. In games with a region or matchmaking-server setting, pick the one closest to $($b.Name) instead of 'auto'."
    }
    if ($DnsResults.Count -gt 1) {
        $cur = $DnsResults | Where-Object { $_.Current } | Select-Object -First 1
        $best = $DnsResults[0]
        if ($cur -and -not $best.Current -and ($cur.Ms - $best.Ms) -ge 5) {
            PR2 'info' ('{0} DNS is faster than yours ({1:0} vs {2:0} ms)' -f $best.Name, $best.Ms, $cur.Ms) 'Click "Use" next to it in the DNS benchmark, or press Boost ping. Faster DNS = quicker server connects and launcher logins (it does not change in-game ping).'
        }
    }
    $off = @($PingBoostIds | ForEach-Object { $TweakById[$_] } | Where-Object { $_ -and -not $_.Active -and (Test-Suitable $_) })
    if ($off.Count -gt 0) { PR2 'warn' "$($off.Count) network optimizations are not active" 'Press "Boost ping" to apply them in one go.' }
    else { PR2 'ok' 'All network optimizations are active' 'Windows is set up for the lowest possible ping.' }
    if (-not $r.Time) { PR2 'info' 'Run the full test' 'Click "Run full test" (about 30 seconds) for router check, game server regions, bufferbloat and DNS benchmark.' }
    foreach ($x in ($recs | Sort-Object { switch ($_.S) { 'warn' { 0 } 'info' { 1 } default { 2 } } })) { [void]$PingRecList.Children.Add((New-RecRow $x)) }
}

function Invoke-PingBoost {
    $res = Invoke-TweakList 'Boost ping' $PingBoostIds 'Apply these network optimizations? Your connection drops for a few seconds while the network adapter restarts.'
    if (-not $res.Run) { return }
    Show-Overlay 'Flushing DNS cache...'
    try { Clear-DnsClientCache; ipconfig /flushdns | Out-Null } catch { }
    $dnsMsg = ''
    if ($DnsResults.Count -gt 1) {
        $cur = $DnsResults | Where-Object { $_.Current } | Select-Object -First 1
        $best = $DnsResults[0]
        if (-not $best.Current -and (-not $cur -or ($cur.Ms - $best.Ms) -ge 5)) {
            try { Set-DnsAll $best.Ip $best.Ip2; foreach ($x in $DnsResults) { $x.Current = ($x.Ip -eq $best.Ip) }; Show-DnsResults; $dnsMsg = "`nDNS switched to $($best.Name) (fastest in your benchmark)." } catch { }
        }
    }
    Hide-Overlay
    Build-PingRecs
    $msg = "$($res.Applied) network optimizations applied.$dnsMsg"
    if (@($res.Failed).Count -gt 0) { $msg += "`n`nSkipped (not supported here):`n - " + (@($res.Failed) -join "`n - ") }
    $msg += "`n`nHonest note: your base ping is set by the distance to the server and your internet provider. These optimizations remove spikes, jitter and delays on your side - for big gains use a LAN cable and fix bufferbloat in the router."
    Set-Status 'Ping boost applied'
    Show-Msg $msg 'Boost ping' | Out-Null
}

# ------------------------------------------------------------------ Input Lag
$script:InputIds = @('mouse-accel', 'pointer-1to1', 'usb-suspend', 'usb-device-power', 'hags', 'game-mode', 'game-dvr', 'fso', 'windowed-opt',
    'win32prio', 'mmcss-games', 'sys-responsiveness', 'timer-res', 'hpet-default', 'core-parking', 'power-throttling', 'ultimate-plan',
    'pcie-aspm', 'gpu-msi', 'sticky-keys', 'dynamic-tick', 'vbs')
$script:InputRowsBuilt = $false
$script:PollResult = 0
$script:LastLat = 0.0
$script:RawHookOn = $false

function Enable-RawHook {
    if ($RawHookOn) { return }
    $h = (New-Object System.Windows.Interop.WindowInteropHelper $Window).Handle
    $src = [System.Windows.Interop.HwndSource]::FromHwnd($h)
    $script:RawHookDelegate = [Delegate]::CreateDelegate([System.Windows.Interop.HwndSourceHook], [SBRaw].GetMethod('Hook'))
    $src.AddHook($RawHookDelegate)
    $script:RawHookOn = $true
}

function Get-SnappedRate([double]$r) {
    foreach ($s in 125, 250, 500, 1000, 2000, 4000, 8000) { if ([Math]::Abs($r - $s) -le $s * 0.15) { return $s } }
    [int]$r
}

function Start-PollTest {
    try {
        Enable-RawHook
        $h = (New-Object System.Windows.Interop.WindowInteropHelper $Window).Handle
        if (-not [SBRaw]::Start($h)) { throw 'Windows did not allow raw mouse input.' }
    } catch { Show-Msg "Polling test could not start: $($_.Exception.Message)" 'Silvan Boost' 'OK' 'Error' | Out-Null; return }
    $script:PollSamples = New-Object System.Collections.Generic.List[double]
    $script:PollStart = Get-Date
    $BtnPollTest.IsEnabled = $false
    $PollHint.Text = 'Move your mouse fast in circles now...'
    if (-not $script:PollTimer) {
        $script:PollTimer = New-Object System.Windows.Threading.DispatcherTimer
        $PollTimer.Interval = [TimeSpan]::FromMilliseconds(100)
        $PollTimer.Add_Tick({
                try {
                    $r = [SBRaw]::RateLast(250)
                    if ($r -gt 0) { $PollSamples.Add([double]$r) }
                    $PollBig.Text = "$r"
                    $left = 5 - ((Get-Date) - $PollStart).TotalSeconds
                    if ($left -gt 0) { $PollHint.Text = ('Move your mouse fast in circles... {0:0}s' -f [Math]::Ceiling($left)) }
                    else { Stop-PollTest }
                } catch { Stop-PollTest }
            })
    }
    $PollTimer.Start()
}

function Stop-PollTest {
    $PollTimer.Stop()
    try { [void][SBRaw]::Stop() } catch { }
    $BtnPollTest.IsEnabled = $true
    $a = $PollSamples.ToArray()
    if ($a.Length -lt 5) { $PollBig.Text = '-'; $PollHint.Text = 'No movement detected - click Start and keep moving the mouse for the whole 5 seconds.'; return }
    [Array]::Sort($a)
    $raw = $a[[int][Math]::Floor(($a.Length - 1) * 0.8)]
    $script:PollResult = Get-SnappedRate $raw
    $PollBig.Text = "$PollResult"
    if ($PollResult -ge 1000) { $PollHint.Text = "Your mouse reports $PollResult times per second - great for competitive play." }
    elseif ($PollResult -ge 500) { $PollHint.Text = "Your mouse reports $PollResult times per second. Set 1000 Hz (or higher) in your mouse software for smoother and faster input." }
    else { $PollHint.Text = "Only $PollResult Hz - that adds up to $([Math]::Round(1000 / [Math]::Max(1, $PollResult), 1)) ms delay. Set 1000 Hz in your mouse software, or consider a gaming mouse." }
    $InPoll.Text = "$PollResult Hz"; $InPollSub.Text = 'measured'
    Write-Log "Mouse polling rate test: $PollResult Hz (raw $raw)"
    Build-InputRecs
}

function Update-InputLive {
    $lat = [double]$Sync.InputLat
    if ($LiveSession -and $lat -gt 0) { $InLat.Text = '{0:0} ms' -f $lat; $InLatSub.Text = "live in $($LiveSession.Name)" }
    elseif ($LastLat -gt 0) { $InLat.Text = '{0:0} ms' -f $LastLat; $InLatSub.Text = 'last measured in a game' }
    else { $InLat.Text = '-'; $InLatSub.Text = 'start a game to measure' }
}

function Get-InputCounts {
    $list = @($InputIds | ForEach-Object { $TweakById[$_] } | Where-Object { $_ -and $_.Risk -ne 'Advanced' -and (Test-Suitable $_) })
    @{ On = @($list | Where-Object { $_.Active }).Count; All = $list.Count }
}

function Build-InputRecs {
    $InputRecList.Children.Clear()
    $recs = New-Object System.Collections.ArrayList
    function IR($s, $t, $x) { [void]$recs.Add(@{ S = $s; T = $t; X = $x }) }
    if ($HW.RefCur -gt 0) {
        $InHz.Text = "$($HW.RefCur) Hz"; $InHzSub.Text = "max $($HW.RefMax) Hz  |  $($HW.ResW) x $($HW.ResH)"
        if ($HW.RefMax -gt $HW.RefCur) { IR 'warn' "Monitor runs at $($HW.RefCur) Hz instead of $($HW.RefMax) Hz" 'Free input lag reduction: Settings > System > Display > Advanced display > highest refresh rate. Use DisplayPort or a high-speed HDMI cable.' }
        else { IR 'ok' "Monitor at its maximum refresh rate ($($HW.RefCur) Hz)" ('A new image every {0:0.0} ms.' -f (1000 / $HW.RefCur)) }
    }
    if ($PollResult -gt 0) {
        if ($PollResult -ge 1000) { IR 'ok' "Mouse polling rate $PollResult Hz" 'Your mouse sends its position fast enough for competitive play.' }
        else { IR 'warn' "Mouse polling rate only $PollResult Hz" 'Set 1000 Hz or higher in your mouse software (G HUB, Synapse, etc.).' }
    } else { IR 'info' 'Test your mouse polling rate' 'Click "Start test" on the left and move the mouse for 5 seconds.' }
    $c = Get-InputCounts
    $InTw.Text = "$($c.On) / $($c.All)"; $InTwSub.Text = 'active (advanced not counted)'
    if ($c.On -lt $c.All) { IR 'warn' "$($c.All - $c.On) input optimizations are not active" 'Press "Max input response" to apply them all at once.' }
    else { IR 'ok' 'All input optimizations are active' 'Windows is set up for the fastest possible input.' }
    if ($LastLat -gt 0) {
        if ($LastLat -le 25) { IR 'ok' ('Measured PC latency: {0:0} ms' -f $LastLat) 'Excellent - time from your input to the image on screen (PC part, measured in-game).' }
        elseif ($LastLat -le 45) { IR 'info' ('Measured PC latency: {0:0} ms' -f $LastLat) 'Good. To go lower: turn on NVIDIA Reflex / AMD Anti-Lag, lower graphics so the GPU is not at 100%, and raise FPS.' }
        else { IR 'warn' ('High PC latency: {0:0} ms' -f $LastLat) 'Usually caused by a GPU at 100% load or VSync. Turn on Reflex / Anti-Lag, turn VSync off, lower graphics settings.' }
    } else { IR 'info' 'Measure your real input latency' 'Keep Silvan Boost open and play a supported game - the Live Monitor measures the time from your click to the image on screen.' }
    foreach ($x in ($recs | Sort-Object { switch ($_.S) { 'warn' { 0 } 'info' { 1 } default { 2 } } })) { [void]$InputRecList.Children.Add((New-RecRow $x)) }
}

function Build-InputGuide {
    $InputGuideList.Children.Clear()
    $g = New-Object System.Collections.ArrayList
    if ($HW.IsNvidia) {
        [void]$g.Add(@{ S = 'info'; T = 'NVIDIA Reflex: On + Boost'; X = 'In every game that has it (Valorant, CS2, Fortnite, Apex, Overwatch, CoD ...). This is the single biggest input lag reduction.' })
        [void]$g.Add(@{ S = 'info'; T = 'NVIDIA Control Panel > Manage 3D settings'; X = 'Low Latency Mode: Ultra (for games without Reflex)  |  Power management mode: Prefer maximum performance  |  Vertical sync: Off  |  Max Frame Rate: Off, or 3 below your refresh rate with G-SYNC.' })
    } elseif ($HW.GpuName -match 'AMD|Radeon') {
        [void]$g.Add(@{ S = 'info'; T = 'AMD Anti-Lag 2 / Anti-Lag: On'; X = 'In AMD Software > Gaming > Graphics, and in-game where available. Turn Radeon Chill and Enhanced Sync off.' })
    } else {
        [void]$g.Add(@{ S = 'info'; T = 'Low-latency mode in your GPU driver'; X = 'Turn on the low-latency option of your graphics driver and turn VSync off.' })
    }
    [void]$g.Add(@{ S = 'info'; T = 'In-game: Fullscreen, VSync off, uncapped FPS'; X = 'Higher FPS = lower input lag, even above your refresh rate. With G-SYNC/FreeSync, cap 3 FPS below the refresh rate instead.' })
    [void]$g.Add(@{ S = 'info'; T = 'Mouse & keyboard in the rear USB ports'; X = 'Plug them directly into the motherboard ports (not a hub, monitor or front panel). Wireless dongle close to the mouse with the extension cable.' })
    [void]$g.Add(@{ S = 'info'; T = 'Mouse: 1000 Hz+, low lift-off, no smoothing'; X = 'In your mouse software: polling rate 1000 Hz or higher, angle snapping off, motion sync off for the lowest delay.' })
    [void]$g.Add(@{ S = 'info'; T = 'Monitor: Game mode and Overdrive'; X = 'Enable the game / low-input-lag mode, set Overdrive to Normal or Fast, turn off eco and dynamic contrast modes.' })
    foreach ($x in $g) { [void]$InputGuideList.Children.Add((New-RecRow $x)) }
}

function Open-InputPage {
    try {
        if (-not $InputRowsBuilt) { Add-FeatRows $InputTweakList $InputIds; Build-InputGuide; $script:InputRowsBuilt = $true }
        Build-InputRecs
        Update-InputLive
    } catch { Write-Log "Input page error: $_" }
}

function Invoke-InputMax {
    $res = Invoke-TweakList 'Max input response' $InputIds 'Apply all input lag optimizations? (Advanced ones are left for you to decide.)'
    if (-not $res.Run) { return }
    Build-InputRecs
    $msg = "$($res.Applied) input optimizations applied."
    if (@($res.Failed).Count -gt 0) { $msg += "`n`nSkipped (not supported here):`n - " + (@($res.Failed) -join "`n - ") }
    if ($RebootPill.Visibility -eq 'Visible') { $msg += "`n`nRestart your PC to finish." }
    $msg += "`n`nNext: set the driver and in-game settings listed on the right (Reflex, Low Latency Mode, VSync off) - they matter just as much."
    Set-Status 'Max input response applied'
    Show-Msg $msg 'Max input response' | Out-Null
}

# ------------------------------------------------------------------ Auto-updater
# Updates are published as version.json + SilvanBoost.ps1 in the owner's GitHub repository.
$script:UpdateUrl  = 'https://raw.githubusercontent.com/silvan3004-pixel/silvan-boost/main/version.json'
$script:UpdateBase = $UpdateUrl.Substring(0, $UpdateUrl.LastIndexOf('/') + 1)
$script:UpdateDir  = Join-Path $DataDir 'update'
$script:PendingUpdate = $null
$script:UpdManual = $false

function Test-UpdateConfigured { $UpdateUrl -notmatch '__OWNER__|__REPO__' }

function Test-NewerVersion([string]$candidate, [string]$current) {
    try {
        $a = [version]$candidate; $b = [version]$current
        $a = [version]::new($a.Major, $a.Minor, [Math]::Max(0, $a.Build))
        $b = [version]::new($b.Major, $b.Minor, [Math]::Max(0, $b.Build))
        return ($a -gt $b)
    } catch { return $false }
}

function Get-Sha256Hex([byte[]]$bytes) {
    $h = [System.Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($h.ComputeHash($bytes)) -replace '-', '').ToLower() } finally { $h.Dispose() }
}

function Get-HttpBytes([string]$url, [int]$timeout = 15000) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $req = [Net.HttpWebRequest]::Create($url)
    $req.Timeout = $timeout; $req.ReadWriteTimeout = $timeout; $req.UserAgent = "SilvanBoost/$AppVersion"
    $req.CachePolicy = New-Object System.Net.Cache.RequestCachePolicy([System.Net.Cache.RequestCacheLevel]::NoCacheNoStore)
    $resp = $req.GetResponse()
    try {
        $ms = New-Object System.IO.MemoryStream
        $resp.GetResponseStream().CopyTo($ms)
        if ($ms.Length -gt 20MB) { throw 'Download too large.' }
        , $ms.ToArray()
    } finally { $resp.Close() }
}

function Start-UpdateCheck([switch]$Manual) {
    $script:UpdManual = [bool]$Manual
    if (-not (Test-UpdateConfigured)) {
        $UpdStatus.Text = 'Automatic updates are not set up in this build.'
        if ($Manual) { Show-Msg 'Automatic updates are not set up in this build.' | Out-Null }
        return
    }
    if ($Sync.UpdState -eq 'checking') { return }
    $UpdStatus.Text = 'Checking for updates...'
    $Sync.UpdState = 'checking'; $Sync.UpdJson = $null; $Sync.UpdErr = $null
    $rs = [runspacefactory]::CreateRunspace(); $rs.Open()
    $rs.SessionStateProxy.SetVariable('Sync', $Sync)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        param($url, $ver)
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $req = [Net.HttpWebRequest]::Create($url + '?t=' + [DateTime]::UtcNow.Ticks)
            $req.Timeout = 8000; $req.ReadWriteTimeout = 8000; $req.UserAgent = "SilvanBoost/$ver"
            $req.CachePolicy = New-Object System.Net.Cache.RequestCachePolicy([System.Net.Cache.RequestCacheLevel]::NoCacheNoStore)
            $resp = $req.GetResponse()
            $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [Text.Encoding]::UTF8)
            $Sync.UpdJson = $sr.ReadToEnd(); $resp.Close()
        } catch { $Sync.UpdErr = $_.Exception.Message }
        $Sync.UpdState = 'done'
    }).AddArgument($UpdateUrl).AddArgument($AppVersion)
    $script:UpdPs = $ps
    [void]$ps.BeginInvoke()
}

function Read-UpdateInfo([string]$json) {
    $j = $json | ConvertFrom-Json
    if (-not $j.version -or -not $j.url -or -not $j.sha256) { throw 'version.json is incomplete (needs version, url and sha256).' }
    if (-not ([string]$j.url).StartsWith($UpdateBase, [StringComparison]::OrdinalIgnoreCase)) { throw 'Update URL points outside the Silvan Boost repository - refused.' }
    if ([string]$j.url -match '\.\.|%2e|%2f|\\|[?#]') { throw 'Update URL is not allowed - refused.' }
    if ([string]$j.sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid checksum in version.json.' }
    $j
}

function Complete-UpdateCheck {
    $manual = $UpdManual
    if ($Sync.UpdErr -or -not $Sync.UpdJson) {
        $UpdStatus.Text = "Could not check for updates ($((Get-Date).ToString('HH:mm')))."
        Write-Log "Update check failed: $($Sync.UpdErr)"
        if ($manual) { Show-Msg "Could not check for updates:`n`n$($Sync.UpdErr)" 'Silvan Boost' 'OK' 'Warning' | Out-Null }
        return
    }
    try { $j = Read-UpdateInfo $Sync.UpdJson }
    catch {
        $UpdStatus.Text = 'Update information is invalid.'
        Write-Log "Update check: $($_.Exception.Message)"
        if ($manual) { Show-Msg "Update information is invalid:`n`n$($_.Exception.Message)" 'Silvan Boost' 'OK' 'Warning' | Out-Null }
        return
    }
    if (-not (Test-NewerVersion ([string]$j.version) $AppVersion)) {
        $UpdStatus.Text = "You have the latest version ($AppVersion) - checked $((Get-Date).ToString('HH:mm'))."
        if ($manual) { Show-Msg "Silvan Boost is up to date (version $AppVersion)." | Out-Null }
        return
    }
    $script:PendingUpdate = $j
    $UpdStatus.Text = "Version $($j.version) is available."
    $BtnUpdNow.Content = "Update to $($j.version)"
    $UpdPill.Visibility = 'Visible'
    $UpdDot.Visibility = 'Visible'
    Write-Log "Update available: $($j.version)"
    $auto = ($State.misc['AutoUpdate'] -ne $false)
    if ($auto -and -not $manual -and -not $LiveSession) { Install-Update $j -Auto }
    elseif ($manual) { Install-Update $j }
}

function Install-Update($j, [switch]$Auto) {
    if (-not $j) { return }
    $notes = (@($j.notes) | Where-Object { $_ } | ForEach-Object { ' - ' + $_ }) -join "`n"
    if (-not $Auto) {
        $r = Show-Msg ("Silvan Boost $($j.version) is available (you have $AppVersion).`n`nWhat's new:`n$notes`n`nInstall now? Silvan Boost restarts automatically.") 'Update available' 'YesNo' 'Question'
        if ([string]$r -ne 'Yes') { return }
    }
    Show-Overlay "Updating Silvan Boost to $($j.version)..."
    try {
        $bytes = Get-HttpBytes ([string]$j.url)
        $hash = Get-Sha256Hex $bytes
        if ($hash -ne ([string]$j.sha256).ToLower()) { throw "Checksum mismatch - the download is damaged or was changed. Update cancelled." }
        $text = [Text.Encoding]::UTF8.GetString($bytes)
        $errs = $null; $tok = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tok, [ref]$errs)
        if (@($errs).Count -gt 0) { throw 'The downloaded script contains errors. Update cancelled.' }
        if ($text -notmatch [regex]::Escape("`$script:AppVersion = '$($j.version)'")) { throw 'Version inside the download does not match version.json. Update cancelled.' }
        New-Item -ItemType Directory -Path $UpdateDir -Force | Out-Null
        $target = Join-Path $UpdateDir 'SilvanBoost.ps1'
        [IO.File]::WriteAllBytes("$target.new", $bytes)
        Move-Item -LiteralPath "$target.new" -Destination $target -Force
        Set-Content -LiteralPath (Join-Path $UpdateDir 'info.txt') -Value @([string]$j.version, $hash) -Encoding ASCII
        $State.misc['UpdNotes'] = @(@($j.notes) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        $State.misc['UpdFrom'] = $AppVersion
        Save-State
        Write-Log "Update $($j.version) downloaded and verified - restarting."
    } catch {
        Hide-Overlay
        Write-Log "Update failed: $($_.Exception.Message)"
        $UpdStatus.Text = 'Update failed - see the activity log.'
        Show-Msg "The update could not be installed:`n`n$($_.Exception.Message)" 'Silvan Boost' 'OK' 'Warning' | Out-Null
        return
    }
    $pwsh = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', "`"$target`"", '-NoElevate', '-JustUpdated')
    if ($LauncherPath) { $argList += @('-LauncherPath', "`"$LauncherPath`"") }
    Start-Process -FilePath $pwsh -ArgumentList $argList -WindowStyle Hidden
    $script:Restarting = $true
    $Window.Close()
}

function Show-UpdatedNotice {
    $from = [string]$State.misc['UpdFrom']
    $notes = (@($State.misc['UpdNotes']) | Where-Object { $_ } | ForEach-Object { ' - ' + $_ }) -join "`n"
    $State.misc.Remove('UpdNotes'); $State.misc.Remove('UpdFrom'); Save-State
    $msg = "Silvan Boost was updated to version $AppVersion"
    if ($from) { $msg += " (from $from)" }
    $msg += '.'
    if ($notes) { $msg += "`n`nWhat's new:`n$notes" }
    Show-Msg $msg 'Update installed' | Out-Null
}

# ------------------------------------------------------------------ Apps: all installed programs + recommended downloads
$script:InstApps = @()
$script:InstLoaded = $false
$script:AppFilter = 'all'
$script:AppSort = 'name'
$script:AppJobs = New-Object System.Collections.ArrayList
$script:KeepRx = 'Visual C\+\+|\.NET|DirectX|Redistributable|Runtime|NVIDIA Graphics Driver|NVIDIA PhysX|NVIDIA HD Audio|NVIDIA USBC|NVIDIA FrameView|Realtek|Intel\(R\) (Management|Chipset|Serial IO|Rapid|Wireless|Bluetooth|Graphics)|AMD (Chipset|Software)|Riot Vanguard|EasyAntiCheat|BattlEye|FACEIT|Microsoft Edge|WebView2|Windows SDK|Update Health|Windows Driver Package|Gaming Services|VCLibs|UI\.Xaml|DesktopAppInstaller|StorePurchaseApp|WindowsStore|SecHealthUI'

function Get-InstalledPrograms {
    $list = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall')) {
        foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            $n = ([string]$p.DisplayName).Trim()
            if (-not $n) { continue }
            if ($p.SystemComponent -eq 1 -or $p.ParentKeyName -or [string]$p.ReleaseType -match 'Update|Hotfix') { continue }
            $u = [string]$p.UninstallString; $q = [string]$p.QuietUninstallString
            if (-not $u -and -not $q) { continue }
            $key = ($n + '|' + [string]$p.DisplayVersion).ToLower()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = 1
            $size = 0.0; try { if ($p.EstimatedSize) { $size = [double]$p.EstimatedSize / 1024 } } catch { }
            $date = $null
            if ([string]$p.InstallDate -match '^\d{8}$') { try { $date = [datetime]::ParseExact([string]$p.InstallDate, 'yyyyMMdd', $null) } catch { } }
            [void]$list.Add(@{ Kind = 'Program'; Name = $n; Ver = [string]$p.DisplayVersion; Pub = ([string]$p.Publisher).Trim(); SizeMB = $size; Date = $date
                    Uninst = $u; Quiet = $q; Pkg = $null; Keep = ($n -match $KeepRx); Row = $null })
        }
    }
    foreach ($a in @(Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { -not $_.IsFramework -and -not $_.NonRemovable -and [string]$_.SignatureKind -ne 'System' -and -not $_.IsResourcePackage })) {
        $n = $null
        try { $dn = [string](Get-AppxPackageManifest -Package $a.PackageFullName -ErrorAction Stop).Package.Properties.DisplayName; if ($dn -and $dn -notmatch '^ms-resource') { $n = $dn } } catch { }
        if (-not $n) { $n = (([string]$a.Name -replace '^[^.]+\.', '') -creplace '([a-z])([A-Z])', '$1 $2') }
        $date = $null; try { $date = (Get-Item -LiteralPath $a.InstallLocation -ErrorAction Stop).CreationTime } catch { }
        $pub = ([string]$a.Publisher -replace '^CN=([^,]+).*$', '$1')
        [void]$list.Add(@{ Kind = 'Store'; Name = $n; Ver = [string]$a.Version; Pub = $pub; SizeMB = 0.0; Date = $date
                Uninst = $null; Quiet = $null; Pkg = $a.PackageFullName; Keep = (($n + ' ' + $a.Name) -match $KeepRx); Row = $null })
    }
    @($list)
}

function New-InstRow($app) {
    $ini = ($app.Name -replace '[^A-Za-z0-9 ]', ' ').Trim()
    $parts = @($ini -split '\s+' | Where-Object { $_ })
    if ($parts.Count -ge 2) { $ini = ($parts[0].Substring(0, 1) + $parts[1].Substring(0, 1)).ToUpper() } elseif ($ini) { $ini = $ini.Substring(0, [Math]::Min(2, $ini.Length)).ToUpper() } else { $ini = '?' }
    $sub = @()
    if ($app.Pub) { $sub += $app.Pub }
    if ($app.Ver) { $sub += "v$($app.Ver)" }
    if ($app.SizeMB -ge 1) { if ($app.SizeMB -ge 1024) { $sub += ('{0:0.0} GB' -f ($app.SizeMB / 1024)) } else { $sub += ('{0:0} MB' -f $app.SizeMB) } }
    if ($app.Date) { $sub += $app.Date.ToString('dd.MM.yyyy') }
    $kindChip = '<Border CornerRadius="6" Padding="7,1" Margin="8,0,0,0" Background="#1A2440" VerticalAlignment="Center"><TextBlock Text="Program" FontSize="10.5" Foreground="#A9B3CC"/></Border>'
    if ($app.Kind -eq 'Store') { $kindChip = '<Border CornerRadius="6" Padding="7,1" Margin="8,0,0,0" Background="#1A3B82F6" VerticalAlignment="Center"><TextBlock Text="Store app" FontSize="10.5" Foreground="#7AA7FF"/></Border>' }
    $keepChip = ''
    if ($app.Keep) { $keepChip = '<Border CornerRadius="6" Padding="7,1" Margin="6,0,0,0" Background="#1AF59E0B" VerticalAlignment="Center"><TextBlock Text="Keep - needed by games/drivers" FontSize="10.5" Foreground="#FBBF24"/></Border>' }
    $xml = @"
<Border $NS BorderBrush="#1A2440" BorderThickness="0,1,0,0" Padding="0,9">
  <DockPanel>
    <Button x:Name="Un" DockPanel.Dock="Right" Style="{DynamicResource SmallBtn}" Content="Uninstall" VerticalAlignment="Center" Margin="10,0,0,0"/>
    <Border DockPanel.Dock="Left" Width="36" Height="36" CornerRadius="9" Background="#1A2440">
      <TextBlock Text="$(X $ini)" FontSize="12" FontWeight="Bold" Foreground="#FF9A3C" HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
    <StackPanel Margin="12,0,0,0" VerticalAlignment="Center">
      <StackPanel Orientation="Horizontal">
        <TextBlock Text="$(X $app.Name)" FontSize="13.5" FontWeight="SemiBold" TextTrimming="CharacterEllipsis" MaxWidth="460"/>
        $kindChip
        $keepChip
      </StackPanel>
      <TextBlock Text="$(X ($sub -join '  |  '))" FontSize="11.5" Foreground="#9AA5BF" Margin="0,2,0,0" TextTrimming="CharacterEllipsis"/>
    </StackPanel>
  </DockPanel>
</Border>
"@
    $row = [System.Windows.Markup.XamlReader]::Parse($xml)
    $b = $row.FindName('Un'); $b.Tag = $app
    $b.Add_Click({ param($s, $e) try { Invoke-AppUninstall $s.Tag } catch { Write-Log "Uninstall error: $_"; Hide-Overlay } })
    $app.Row = $row
    $row
}

function Load-InstalledApps {
    Show-Overlay 'Reading installed apps...'
    try {
        $script:InstApps = Get-InstalledPrograms
        $InstList.Children.Clear()
        foreach ($a in $InstApps) { $a.Row = $null }
        $script:InstLoaded = $true
        Show-InstalledApps
    } catch { Write-Log "Installed apps error: $_" }
    Hide-Overlay
}

function Show-InstalledApps {
    $q = $AppSearch.Text.Trim()
    $list = @($InstApps | Where-Object {
            ($AppFilter -eq 'all' -or ($AppFilter -eq 'prog' -and $_.Kind -eq 'Program') -or ($AppFilter -eq 'store' -and $_.Kind -eq 'Store')) -and
            (-not $q -or $_.Name.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $_.Pub.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0) })
    switch ($AppSort) {
        'size' { $list = @($list | Sort-Object @{ Expression = { $_.SizeMB }; Descending = $true }, @{ Expression = { $_.Name } }) }
        'date' { $list = @($list | Sort-Object @{ Expression = { if ($_.Date) { $_.Date } else { [datetime]::MinValue } }; Descending = $true }) }
        default { $list = @($list | Sort-Object { $_.Name }) }
    }
    $InstList.Children.Clear()
    foreach ($a in $list) {
        if (-not $a.Row) { [void](New-InstRow $a) }
        [void]$InstList.Children.Add($a.Row)
    }
    $progs = @($InstApps | Where-Object { $_.Kind -eq 'Program' }).Count
    $store = $InstApps.Count - $progs
    $gb = (($InstApps | Measure-Object SizeMB -Sum).Sum) / 1024
    $AppsAllSum.Text = ('{0} programs  |  {1} Store apps  |  about {2:0.0} GB (programs that report their size)  |  showing {3}' -f $progs, $store, $gb, $list.Count)
}

function Split-Command([string]$cmd) {
    $cmd = $cmd.Trim()
    if ($cmd -match '(?i)msiexec(\.exe)?\s.*?(\{[0-9A-F-]{36}\})') { return @('msiexec.exe', "/x $($Matches[2])") }
    if ($cmd -match '^"([^"]+)"\s*(.*)$') { return @($Matches[1], $Matches[2]) }
    if ($cmd -match '^(.+?\.exe)\s*(.*)$') { return @($Matches[1], $Matches[2]) }
    @($cmd, '')
}

function Invoke-AppUninstall($app) {
    if (-not $app) { return }
    $warn = ''
    if ($app.Keep) { $warn = "`n`nWARNING: this looks like a runtime, driver or anti-cheat component. Games or drivers may stop working without it." }
    $r = Show-Msg "Uninstall '$($app.Name)'?$warn" 'Uninstall' 'YesNo' $(if ($app.Keep) { 'Warning' } else { 'Question' })
    if ([string]$r -ne 'Yes') { return }
    if ($app.Kind -eq 'Store') {
        Show-Overlay "Removing $($app.Name)..."
        try {
            Remove-AppxPackage -Package $app.Pkg -ErrorAction Stop
            Write-Log "Removed Store app: $($app.Name)"
            $script:InstApps = @($InstApps | Where-Object { $_ -ne $app })
            Show-InstalledApps
            Set-Status "$($app.Name) removed"
        } catch { Show-Msg "Could not remove $($app.Name):`n`n$($_.Exception.Message)" 'Silvan Boost' 'OK' 'Error' | Out-Null }
        Hide-Overlay
        return
    }
    $cmd = $app.Uninst; if (-not $cmd) { $cmd = $app.Quiet }
    $parts = Split-Command $cmd
    try {
        if ($parts[1]) { $p = Start-Process -FilePath $parts[0] -ArgumentList $parts[1] -PassThru -ErrorAction Stop }
        else { $p = Start-Process -FilePath $parts[0] -PassThru -ErrorAction Stop }
        Write-Log "Uninstaller started for $($app.Name): $cmd"
        [void]$AppJobs.Add(@{ Kind = 'uninstall'; Proc = $p; App = $app; Start = Get-Date })
        Set-Status "Uninstalling $($app.Name) - follow the uninstaller window..."
    } catch {
        Show-Msg "The uninstaller of $($app.Name) could not be started:`n`n$($_.Exception.Message)`n`nTry Windows Settings > Apps > Installed apps." 'Silvan Boost' 'OK' 'Error' | Out-Null
    }
}

# ---- recommended downloads (winget IDs checked against the official winget repository)
function RA($Id, $Name, $Cat, $Desc, $Web, $Rx, $Need = $null) { @{ Id = $Id; Name = $Name; Cat = $Cat; Desc = $Desc; Web = $Web; Rx = $Rx; Need = $Need; Card = $null; State = '' } }
$script:RecApps = @(
    (RA $null 'NVIDIA App' 'Drivers' 'Official NVIDIA driver updates, game settings, Reflex/overlay and instant replay. Keep your GPU driver current.' 'https://www.nvidia.com/en-us/software/nvidia-app/' '^NVIDIA App' 'nvidia'),
    (RA $null 'AMD Software: Adrenalin' 'Drivers' 'Official AMD graphics driver with Anti-Lag, overlay and game profiles.' 'https://www.amd.com/en/support/download/drivers.html' 'AMD Software' 'amd'),
    (RA 'Wagnardsoft.DisplayDriverUninstaller' 'Display Driver Uninstaller (DDU)' 'Drivers' 'Removes a broken or old graphics driver completely before a clean reinstall - fixes many stutter and crash problems.' 'https://www.wagnardsoft.com/' $null),
    (RA 'TechPowerUp.NVCleanstall' 'NVCleanstall' 'Drivers' 'Installs NVIDIA drivers without telemetry and extra components you do not need.' 'https://www.techpowerup.com/nvcleanstall/' 'NVCleanstall' 'nvidia'),
    (RA 'Guru3D.Afterburner' 'MSI Afterburner' 'Monitoring' 'In-game overlay for FPS, temperatures and usage (with RivaTuner), plus fan curves and GPU tuning.' 'https://www.msi.com/Landing/afterburner/graphics-cards' 'MSI Afterburner'),
    (RA 'REALiX.HWiNFO' 'HWiNFO' 'Monitoring' 'Shows every sensor in your PC: temperatures, clocks, power and throttling - the best tool to find hardware problems.' 'https://www.hwinfo.com/' 'HWiNFO'),
    (RA 'CPUID.CPU-Z' 'CPU-Z' 'Monitoring' 'Details about your CPU, motherboard and RAM - check that your RAM runs at its XMP/EXPO speed.' 'https://www.cpuid.com/softwares/cpu-z.html' 'CPU-Z'),
    (RA 'TechPowerUp.GPU-Z' 'GPU-Z' 'Monitoring' 'Details about your graphics card: Resizable BAR, PCIe link, clocks and sensors.' 'https://www.techpowerup.com/gpuz/' 'GPU-Z'),
    (RA 'Resplendence.LatencyMon' 'LatencyMon' 'Monitoring' 'Finds drivers that cause audio crackling, micro-stutter and input delay (DPC latency).' 'https://www.resplendence.com/latencymon' 'LatencyMon'),
    (RA 'BitSum.ProcessLasso' 'Process Lasso' 'Performance' 'Keeps background programs from stealing CPU time from your game automatically (ProBalance).' 'https://bitsum.com/' 'Process Lasso'),
    (RA 'CrystalDewWorld.CrystalDiskInfo' 'CrystalDiskInfo' 'Storage' 'Shows the health and temperature of your SSDs and hard drives - spot a dying drive early.' 'https://crystalmark.info/' 'CrystalDiskInfo'),
    (RA 'AntibodySoftware.WizTree' 'WizTree' 'Storage' 'Shows in seconds which folders fill up your drive, so you can free space for games.' 'https://diskanalyzer.com/' 'WizTree'),
    (RA 'Microsoft.Sysinternals.Autoruns' 'Autoruns' 'Performance' 'Microsoft tool that shows everything that starts with Windows - for advanced cleanup.' 'https://learn.microsoft.com/sysinternals/downloads/autoruns' $null),
    (RA 'OBSProject.OBSStudio' 'OBS Studio' 'Gaming' 'Free recording and streaming - use the NVENC / AMF hardware encoder for almost no FPS loss.' 'https://obsproject.com/' 'OBS Studio'),
    (RA '7zip.7zip' '7-Zip' 'Tools' 'Free, fast archive tool for zip, rar and 7z files (mods, configs, tools).' 'https://www.7-zip.org/' '7-Zip'),
    (RA 'Valve.Steam' 'Steam' 'Gaming' 'The biggest PC game store and launcher.' 'https://store.steampowered.com/' '^Steam$'),
    (RA 'EpicGames.EpicGamesLauncher' 'Epic Games Launcher' 'Gaming' 'Launcher for Fortnite, Rocket League and the weekly free games.' 'https://store.epicgames.com/' 'Epic Games Launcher')
)

function Get-Winget {
    $c = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $p = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
    if (Test-Path -LiteralPath $p) { return $p }
    $null
}

function Update-RecCard($r) {
    $c = $r.Card; if (-not $c) { return }
    $st = $c.FindName('St'); $bi = $c.FindName('Inst')
    $installed = $false
    if ($r.Rx) { $installed = (@($InstApps | Where-Object { $_.Name -match $r.Rx }).Count -gt 0) }
    if ($r.State -eq 'installing') { $st.Text = 'Installing...'; $st.Foreground = Get-Brush '#FFB06A'; $bi.IsEnabled = $false }
    elseif ($installed -or $r.State -eq 'done') { $st.Text = 'Installed'; $st.Foreground = Get-Brush '#5BE39A'; $bi.Content = 'Reinstall'; $bi.IsEnabled = [bool]$r.Id }
    elseif ($r.State -eq 'failed') { $st.Text = 'Install failed - use Website'; $st.Foreground = Get-Brush '#F87171'; $bi.IsEnabled = [bool]$r.Id }
    else { $st.Text = $(if ($r.Id) { 'Not installed' } else { 'Download from the official website' }); $st.Foreground = Get-Brush '#9AA5BF'; $bi.IsEnabled = [bool]$r.Id }
    if (-not $r.Id) { $bi.Visibility = 'Collapsed' }
}

function Build-Recommended {
    if (-not $InstLoaded) { $script:InstApps = Get-InstalledPrograms; $script:InstLoaded = $true }
    $RecGrid.Children.Clear()
    foreach ($r in $RecApps) {
        if ($r.Need -eq 'nvidia' -and -not $HW.IsNvidia) { continue }
        if ($r.Need -eq 'amd' -and [string]$HW.GpuName -notmatch 'AMD|Radeon') { continue }
        $xml = @"
<Border $NS Style="{DynamicResource Card}" Margin="0,0,12,12" Padding="16,14">
  <DockPanel>
    <DockPanel DockPanel.Dock="Top">
      <Border CornerRadius="6" Padding="8,2" Background="#1A2440" HorizontalAlignment="Left"><TextBlock Text="$(X $r.Cat)" FontSize="10.5" Foreground="#A9B3CC"/></Border>
    </DockPanel>
    <Border DockPanel.Dock="Bottom" BorderBrush="#1A2440" BorderThickness="0,1,0,0" Padding="0,10,0,0" Margin="0,12,0,0">
      <DockPanel>
        <Button x:Name="Web" DockPanel.Dock="Right" Style="{DynamicResource GhostBtn}" Padding="12,5" FontSize="12" Content="Website" Margin="8,0,0,0"/>
        <Button x:Name="Inst" DockPanel.Dock="Right" Style="{DynamicResource SmallBtn}" Content="Install"/>
        <TextBlock x:Name="St" Text="" FontSize="12" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
      </DockPanel>
    </Border>
    <StackPanel Margin="0,10,0,0">
      <TextBlock Text="$(X $r.Name)" FontSize="15" FontWeight="SemiBold" TextWrapping="Wrap"/>
      <TextBlock Text="$(X $r.Desc)" FontSize="12.5" Foreground="#9AA5BF" TextWrapping="Wrap" Margin="0,6,0,0" LineHeight="18"/>
    </StackPanel>
  </DockPanel>
</Border>
"@
        $card = [System.Windows.Markup.XamlReader]::Parse($xml)
        $r.Card = $card
        $card.FindName('Web').Tag = $r; $card.FindName('Inst').Tag = $r
        $card.FindName('Web').Add_Click({ param($s, $e) try { Start-Process ([string]$s.Tag.Web) } catch { } })
        $card.FindName('Inst').Add_Click({ param($s, $e) try { Install-RecApp $s.Tag } catch { Write-Log "Install error: $_" } })
        Update-RecCard $r
        [void]$RecGrid.Children.Add($card)
    }
    $wg = Get-Winget
    if ($wg) { $RecNote.Text = 'Install downloads the official version through winget, the Windows package manager, and installs it silently. Website opens the official download page.' }
    else { $RecNote.Text = 'winget (Windows package manager) was not found on this PC - use Website to download, or install "App Installer" from the Microsoft Store to enable one-click installs.' }
}

function Install-RecApp($r) {
    if (-not $r.Id) { Start-Process $r.Web; return }
    $wg = Get-Winget
    if (-not $wg) { Show-Msg "winget is not available on this PC. The official website will open instead." | Out-Null; Start-Process $r.Web; return }
    $res = Show-Msg "Install $($r.Name)?`n`nIt is downloaded from the official Windows package source (winget, ID: $($r.Id)) and installed silently. By installing you accept the license of $($r.Name)." 'Install app' 'YesNo' 'Question'
    if ([string]$res -ne 'Yes') { return }
    try {
        $p = Start-Process -FilePath $wg -ArgumentList @('install', '--id', $r.Id, '-e', '--silent', '--source', 'winget', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity') -PassThru -WindowStyle Hidden -ErrorAction Stop
        $r.State = 'installing'; Update-RecCard $r
        [void]$AppJobs.Add(@{ Kind = 'install'; Proc = $p; Rec = $r; Start = Get-Date })
        Write-Log "winget install started: $($r.Id)"
        Set-Status "Installing $($r.Name)..."
    } catch { $r.State = 'failed'; Update-RecCard $r; Write-Log "winget start failed: $($_.Exception.Message)" }
}

function Update-AppJobs {
    if ($AppJobs.Count -eq 0) { return }
    foreach ($j in @($AppJobs)) {
        if (-not $j.Proc.HasExited -and ((Get-Date) - $j.Start).TotalMinutes -lt 30) { continue }
        $AppJobs.Remove($j)
        $code = 0; try { $code = $j.Proc.ExitCode } catch { }
        if ($j.Kind -eq 'install') {
            $r = $j.Rec
            if ($code -eq 0 -or $code -eq -1978335189 -or $code -eq -1978335135) { $r.State = 'done'; Set-Status "$($r.Name) installed"; Write-Log "Installed $($r.Id)" }
            else { $r.State = 'failed'; Set-Status "$($r.Name) could not be installed (code $code)"; Write-Log "winget install $($r.Id) failed with code $code" }
            $script:InstLoaded = $false
            try { $script:InstApps = Get-InstalledPrograms; $script:InstLoaded = $true } catch { }
            Update-RecCard $r
        } else {
            Write-Log "Uninstaller for $($j.App.Name) finished (code $code)"
            try { $script:InstApps = Get-InstalledPrograms; foreach ($a in $InstApps) { $a.Row = $null }; Show-InstalledApps } catch { }
            $still = @($InstApps | Where-Object { $_.Name -eq $j.App.Name }).Count -gt 0
            if ($still) { Set-Status "$($j.App.Name) is still installed (uninstall cancelled or needs a restart)" } else { Set-Status "$($j.App.Name) uninstalled" }
        }
    }
}

function Show-AppsTab([string]$t) {
    $AppsBloatView.Visibility = $(if ($t -eq 'bloat') { 'Visible' } else { 'Collapsed' })
    $AppsBloatBtns.Visibility = $AppsBloatView.Visibility
    $AppsAllView.Visibility = $(if ($t -eq 'all') { 'Visible' } else { 'Collapsed' })
    $AppsRecView.Visibility = $(if ($t -eq 'rec') { 'Visible' } else { 'Collapsed' })
    if ($t -eq 'bloat') { Load-Apps }
    elseif ($t -eq 'all') { $AppsSub.Text = 'Every program and Store app on this PC - search, sort and uninstall.'; if (-not $InstLoaded) { Load-InstalledApps } else { Show-InstalledApps } }
    else { $AppsSub.Text = 'Free tools that help with performance, monitoring and drivers - one click to install.'; Show-Overlay 'Checking installed apps...'; try { Build-Recommended } catch { Write-Log "Recommended error: $_" }; Hide-Overlay }
}

# ------------------------------------------------------------------ Ping tools
function Test-PrivateIp([string]$ip) { $ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.)' }

function Add-ToolRow($panel, [string]$left, [string]$mid, [string]$right, [string]$col = '#E8ECF5', [string]$sub = '') {
    $subX = ''
    if ($sub) { $subX = "<TextBlock Text=`"$(X $sub)`" FontSize=`"11`" Foreground=`"#7F8BA6`" TextTrimming=`"CharacterEllipsis`"/>" }
    $xml = @"
<Border $NS BorderBrush="#1A2440" BorderThickness="0,1,0,0" Padding="0,6">
  <DockPanel>
    <TextBlock DockPanel.Dock="Right" Text="$(X $right)" FontSize="12.5" FontWeight="SemiBold" Foreground="$col" Width="110" TextAlignment="Right" VerticalAlignment="Center"/>
    <TextBlock DockPanel.Dock="Left" Text="$(X $left)" FontSize="12" Foreground="#7F8BA6" Width="34" VerticalAlignment="Center"/>
    <StackPanel VerticalAlignment="Center">
      <TextBlock Text="$(X $mid)" FontSize="12.5" TextTrimming="CharacterEllipsis"/>
      $subX
    </StackPanel>
  </DockPanel>
</Border>
"@
    [void]$panel.Children.Add([System.Windows.Markup.XamlReader]::Parse($xml))
}

function Get-MsColor([double]$ms) { if ($ms -lt 0) { '#F87171' } elseif ($ms -lt 30) { '#5BE39A' } elseif ($ms -lt 60) { '#FBBF24' } else { '#F87171' } }

# ---- route analysis
function Get-RouteVerdict($hops) {
    $final = $hops | Where-Object { $_.Ip } | Select-Object -Last 1
    # find where it goes wrong (loss or latency that carries through to the end)
    $verdict = 'Route looks clean - no hop adds noticeable delay or loss.'
    $good = @($hops | Where-Object { $_.Ip -and $_.Avg -ge 0 })
    if ($final -and $good.Count -ge 2) {
        $blame = $null; $why = ''
        if ($final.Loss -gt 0) {
            for ($k = 0; $k -lt $good.Count; $k++) {
                $rest = @($good[$k..($good.Count - 1)])
                if (@($rest | Where-Object { $_.Loss -le 0 }).Count -eq 0) { $blame = $good[$k]; $why = ('packet loss starts at hop {0} and continues to the end' -f $good[$k].Ttl); break }
            }
        }
        if (-not $blame) {
            $prev = 0.0
            foreach ($h in $good) {
                if (($h.Avg - $prev) -ge 25 -and $final.Avg -ge ($h.Avg - 5) -and $h.Ttl -le 3) { $blame = $h; $why = ('ping jumps by {0:0} ms at hop {1}' -f ($h.Avg - $prev), $h.Ttl); break }
                $prev = [Math]::Max($prev, $h.Avg)
            }
            if (-not $blame -and $good[0].Jit -gt 5) { $blame = $good[0]; $why = ('your router answers unevenly (jitter {0:0.0} ms)' -f $good[0].Jit) }
        }
        if ($blame) {
            if ($blame.Ttl -eq 1) { $verdict = "Problem found in YOUR HOME NETWORK: $why. Fix: use a LAN cable instead of Wi-Fi, restart the router, check the cable, stop downloads on other devices." }
            elseif ($blame.Ttl -le 3) { $verdict = "Problem found at YOUR INTERNET PROVIDER: $why. Fix: restart the router; if it stays like this, contact your provider and show them this result." }
            else { $verdict = "Problem found in the wider internet: $why. This is outside your home - try another game server region." }
        }
        $verdict += (' Final ping: {0:0} ms.' -f $final.Avg)
    }
    $verdict
}

function Invoke-RouteTest([string]$target = '1.1.1.1') {
    $RouteList.Children.Clear(); $RouteSum.Text = ''
    $p = New-Object System.Net.NetworkInformation.Ping
    $buf = [byte[]](1..32)
    $hops = New-Object System.Collections.ArrayList
    $miss = 0
    try {
        for ($ttl = 1; $ttl -le 24; $ttl++) {
            Show-Overlay "Tracing the route to $target...`nhop $ttl"
            $addr = $null; $done = $false
            try {
                $r = $p.Send($target, 1000, $buf, (New-Object System.Net.NetworkInformation.PingOptions($ttl, $true)))
                if ($r.Status -eq 'TtlExpired' -or $r.Status -eq 'Success') { $addr = $r.Address.ToString() }
                if ($r.Status -eq 'Success') { $done = $true }
            } catch { }
            [void]$hops.Add(@{ Ttl = $ttl; Ip = $addr; Avg = -1.0; Loss = 100.0; Jit = 0.0 })
            if ($done) { break }
            if ($addr) { $miss = 0 } else { $miss++ }
            if ($miss -ge 4 -and $ttl -ge 8) { break }
        }
        $i = 0
        foreach ($h in $hops) {
            $i++
            if (-not $h.Ip) { continue }
            Show-Overlay "Measuring each hop... ($i of $($hops.Count))`n$($h.Ip)"
            $st = Get-PingStats (Measure-Pings $h.Ip 8 40)
            $h.Avg = $st.Avg; $h.Loss = $st.Loss; $h.Jit = $st.Jit
        }
    } finally { Hide-Overlay }
    $final = $hops | Where-Object { $_.Ip } | Select-Object -Last 1
    foreach ($h in $hops) {
        $where = 'Internet'
        if ($h.Ttl -eq 1) { $where = 'Your router' } elseif ($h.Ttl -le 3 -or (Test-PrivateIp $h.Ip)) { $where = 'Your internet provider' }
        if (-not $h.Ip) { Add-ToolRow $RouteList "#$($h.Ttl)" '* no reply' 'hidden' '#7F8BA6' $where; continue }
        $txt = '{0:0} ms' -f $h.Avg; if ($h.Avg -lt 0) { $txt = 'no reply' }
        if ($h.Loss -gt 0 -and $h.Avg -ge 0) { $txt += (' | {0:0}% loss' -f $h.Loss) }
        Add-ToolRow $RouteList "#$($h.Ttl)" $h.Ip $txt (Get-MsColor $h.Avg) $where
    }
    $verdict = Get-RouteVerdict $hops
    $RouteSum.Text = $verdict
    Write-Log "Route test to ${target}: $verdict"
}

# ---- Valve / CS2 servers
function Test-ValveServers {
    $ValveList.Children.Clear()
    Show-Overlay 'Downloading the Valve server list...'
    try {
        $bytes = Get-HttpBytes 'https://api.steampowered.com/ISteamApps/GetSDRConfig/v1/?appid=730' 10000
        $j = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        if (-not $j.pops) { throw 'unexpected format' }
        $items = New-Object System.Collections.ArrayList
        foreach ($pr in $j.pops.PSObject.Properties) {
            $pop = $pr.Value
            $ip = $null
            foreach ($rl in @($pop.relays)) { if ($rl.ipv4) { $ip = [string]$rl.ipv4; break } }
            if (-not $ip) { continue }
            $desc = [string]$pop.desc; if (-not $desc) { $desc = $pr.Name }
            [void]$items.Add(@{ Code = $pr.Name; Desc = $desc; Ip = $ip; Best = -1.0 })
        }
        if ($items.Count -eq 0) { throw 'no servers in the list' }
        for ($round = 0; $round -lt 3; $round++) {
            Show-Overlay ("Pinging {0} Valve server locations... (round {1} of 3)" -f $items.Count, ($round + 1))
            $tasks = @()
            foreach ($it in $items) { $tasks += , @($it, (New-Object System.Net.NetworkInformation.Ping).SendPingAsync($it.Ip, 1500)) }
            try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($tasks | ForEach-Object { $_[1] }), 4000) } catch { }
            foreach ($t in $tasks) {
                try {
                    if ($t[1].IsCompleted -and -not $t[1].IsFaulted -and $t[1].Result.Status -eq 'Success') {
                        $v = [double]$t[1].Result.RoundtripTime
                        if ($t[0].Best -lt 0 -or $v -lt $t[0].Best) { $t[0].Best = $v }
                    }
                } catch { }
            }
            Flush-UI
        }
        $sorted = @($items | Where-Object { $_.Best -ge 0 } | Sort-Object { $_.Best } | Select-Object -First 12)
        if ($sorted.Count -eq 0) { throw 'no Valve server answered' }
        foreach ($it in $sorted) { Add-ToolRow $ValveList $it.Code $it.Desc ('{0:0} ms' -f $it.Best) (Get-MsColor $it.Best) $it.Ip }
        $ValveSum.Text = ('Your closest Valve servers: {0} ({1:0} ms). CS2 matchmaking prefers the lowest ping automatically - set "Max acceptable matchmaking ping" in CS2 to about {2} to stay on the closest servers.' -f $sorted[0].Desc, $sorted[0].Best, [int]([Math]::Max(30, [Math]::Ceiling(($sorted[0].Best + 20) / 10) * 10)))
        Write-Log ("Valve server test: best {0} {1:0} ms" -f $sorted[0].Desc, $sorted[0].Best)
    } catch {
        $ValveSum.Text = "Could not test the Valve servers: $($_.Exception.Message)"
        Write-Log "Valve server test failed: $($_.Exception.Message)"
    }
    Hide-Overlay
}

# ---- apps using the internet
$script:BwHints = @{
    'onedrive' = 'Cloud sync - pause it while gaming'; 'steam' = 'Steam - pause downloads in the Downloads page'; 'steamwebhelper' = 'Steam browser / store'
    'epicgameslauncher' = 'Epic launcher - may be downloading updates'; 'battle.net' = 'Battle.net - may be downloading updates'; 'agent' = 'Battle.net update agent'
    'eadesktop' = 'EA app - may be downloading'; 'riotclientservices' = 'Riot Client'; 'qbittorrent' = 'Torrent client - uses all your bandwidth'
    'utorrent' = 'Torrent client - uses all your bandwidth'; 'bittorrent' = 'Torrent client - uses all your bandwidth'; 'chrome' = 'Browser (videos, downloads)'
    'msedge' = 'Browser (videos, downloads)'; 'firefox' = 'Browser (videos, downloads)'; 'opera' = 'Browser'; 'brave' = 'Browser'
    'discord' = 'Discord (voice, streams)'; 'spotify' = 'Music streaming'; 'svchost' = 'Windows services (Windows Update / Delivery Optimization)'
    'msmpeng' = 'Defender updates'; 'dropbox' = 'Cloud sync'; 'googledrivefs' = 'Cloud sync'; 'obs64' = 'Streaming / recording'
}
function Invoke-BandwidthScan {
    $BwList.Children.Clear()
    Show-Overlay 'Looking for apps that use your internet...'
    try {
        $conns = @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0|::$)' -and -not (Test-PrivateIp $_.RemoteAddress) })
        $byPid = @{}
        foreach ($c in $conns) { $byPid[[int]$c.OwningProcess] = 1 + [int]$byPid[[int]$c.OwningProcess] }
        $io = @{}
        foreach ($q in @(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -Property IDProcess, IODataBytesPersec -ErrorAction SilentlyContinue)) { $io[[int]$q.IDProcess] = [double]$q.IODataBytesPersec }
        $rows = New-Object System.Collections.ArrayList
        foreach ($procId in $byPid.Keys) {
            $pr = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if (-not $pr -or $procId -eq $PID) { continue }
            [void]$rows.Add(@{ Pid = $procId; Name = $pr.ProcessName; Conns = $byPid[$procId]; Rate = [double]$io[$procId] })
        }
        $rows = @($rows | Sort-Object @{ Expression = { $_.Rate }; Descending = $true }, @{ Expression = { $_.Conns }; Descending = $true } | Select-Object -First 12)
        foreach ($r in $rows) {
            $n = $r.Name.ToLower()
            $hint = "$($r.Conns) internet connection(s)"
            if ($BwHints.ContainsKey($n)) { $hint = $BwHints[$n] + "  |  $($r.Conns) connection(s)" }
            $rate = '{0:0.0} MB/s' -f ($r.Rate / 1MB); if ($r.Rate -lt 100KB) { $rate = 'idle' }
            $col = '#9AA5BF'; if ($r.Rate -ge 2MB) { $col = '#F87171' } elseif ($r.Rate -ge 300KB) { $col = '#FBBF24' }
            $path = $null; try { $path = (Get-Process -Id $r.Pid -ErrorAction Stop).Path } catch { }
            $canClose = -not (Test-ProcProtected $r.Name $path)
            $btn = ''
            if ($canClose) { $btn = '<Button x:Name="Cl" DockPanel.Dock="Right" Style="{DynamicResource SmallBtn}" Content="Close" Margin="10,0,0,0" VerticalAlignment="Center"/>' }
            $xml = @"
<Border $NS BorderBrush="#1A2440" BorderThickness="0,1,0,0" Padding="0,6">
  <DockPanel>
    $btn
    <TextBlock DockPanel.Dock="Right" Text="$rate" FontSize="12.5" FontWeight="SemiBold" Foreground="$col" Width="80" TextAlignment="Right" VerticalAlignment="Center"/>
    <StackPanel VerticalAlignment="Center">
      <TextBlock Text="$(X $r.Name)" FontSize="12.5" FontWeight="SemiBold"/>
      <TextBlock Text="$(X $hint)" FontSize="11" Foreground="#7F8BA6" TextTrimming="CharacterEllipsis"/>
    </StackPanel>
  </DockPanel>
</Border>
"@
            $row = [System.Windows.Markup.XamlReader]::Parse($xml)
            $cl = $row.FindName('Cl')
            if ($cl) {
                $cl.Tag = $r.Name
                $cl.Add_Click({ param($s, $e)
                        $nm = [string]$s.Tag
                        $ok = Show-Msg "Close $nm now? Unsaved work in it is lost." 'Close app' 'YesNo' 'Question'
                        if ([string]$ok -eq 'Yes') { Get-Process -Name $nm -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Kill() } catch { } }; Write-Log "Closed $nm (bandwidth)"; Invoke-BandwidthScan }
                    })
            }
            [void]$BwList.Children.Add($row)
        }
        if ($rows.Count -eq 0) { $BwSum.Text = 'No app is connected to the internet right now.' }
        else { $BwSum.Text = 'Sorted by current activity (network + disk). Red = heavy traffic right now - close or pause it while you play.' }
    } catch { $BwSum.Text = "Scan failed: $($_.Exception.Message)" }
    Hide-Overlay
}

# ---- Wi-Fi channel check
function Invoke-WifiScan {
    $WifiList.Children.Clear()
    $ci = Get-ConnInfo
    $o = (netsh wlan show networks mode=bssid) | Out-String
    $nets = New-Object System.Collections.ArrayList
    $sig = $null
    foreach ($line in ($o -split "`r?`n")) {
        if ($line -match '^\s*Signal\s*:\s*(\d+)\s*%') { $sig = [int]$Matches[1] }
        elseif ($line -match '^\s*(Channel|Kanal)\s*:\s*(\d+)' -and $null -ne $sig) { [void]$nets.Add(@{ Ch = [int]$Matches[2]; Sig = $sig }); $sig = $null }
    }
    if ($nets.Count -eq 0) {
        $WifiSum.Text = 'Windows returned no nearby networks. On Windows 11 the Wi-Fi scan needs Location access: Settings > Privacy & security > Location > on (and allow desktop apps). If you turned off location with Silvan Boost, turn it on for the scan.'
        return
    }
    $myCh = 0
    $w = (netsh wlan show interfaces) | Out-String
    if ($w -match '(?m)^\s*(Channel|Kanal)\s*:\s*(\d+)') { $myCh = [int]$Matches[2] }
    $load = @{}
    foreach ($n in $nets) { $load[$n.Ch] = [double]$load[$n.Ch] + $n.Sig / 100.0 }
    $chs = @($load.Keys | Sort-Object)
    foreach ($c in $chs) {
        $cnt = @($nets | Where-Object { $_.Ch -eq $c }).Count
        $band = $(if ($c -le 14) { '2.4 GHz' } else { '5/6 GHz' })
        $mark = ''; if ($c -eq $myCh) { $mark = '  <- you' }
        $col = '#5BE39A'; if ($cnt -ge 3) { $col = '#FBBF24' }; if ($cnt -ge 6) { $col = '#F87171' }
        Add-ToolRow $WifiList "ch" ("Channel $c ($band)$mark") ("$cnt network(s)") $col
    }
    $sum = "Found $($nets.Count) access points nearby."
    if ($myCh -gt 0 -and $myCh -le 14) {
        $score = @{}
        foreach ($c in 1, 6, 11) { $s = 0.0; foreach ($n in $nets) { if ($n.Ch -le 14 -and [Math]::Abs($n.Ch - $c) -lt 5) { $s += $n.Sig / 100.0 * (1 - [Math]::Abs($n.Ch - $c) / 5) } }; $score[$c] = $s }
        $best = @($score.GetEnumerator() | Sort-Object Value)[0].Key
        $sum += " You are on 2.4 GHz channel $myCh. Best would be 5 GHz; on 2.4 GHz, channel $best is the least crowded (only 1, 6 or 11 avoid overlap). Change it in your router's Wi-Fi settings."
    } elseif ($myCh -gt 14) {
        $same = @($nets | Where-Object { $_.Ch -eq $myCh }).Count - 1
        $free = @(36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140) | Where-Object { -not $load.ContainsKey($_) } | Select-Object -First 1
        if ($same -ge 2 -and $free) { $sum += " You are on 5 GHz channel $myCh shared with $same other network(s). Channel $free looks free - set it in your router." }
        else { $sum += " You are on 5 GHz channel $myCh - good, little interference." }
    }
    $WifiSum.Text = $sum
}

# ---- MTU
function Invoke-MtuTest {
    $p = New-Object System.Net.NetworkInformation.Ping
    $opt = New-Object System.Net.NetworkInformation.PingOptions(64, $true)
    $test = { param($size) try { $r = $p.Send('1.1.1.1', 1500, (New-Object byte[] $size), $opt); return ($r.Status -eq 'Success') } catch { return $false } }
    Show-Overlay 'Testing the largest packet size your connection allows...'
    $mtu = 0
    try {
        if (& $test 1472) { $mtu = 1500 }
        elseif (& $test 1200) {
            $lo = 1200; $hi = 1471
            while ($lo -lt $hi) { $mid = [int][Math]::Ceiling(($lo + $hi) / 2); if (& $test $mid) { $lo = $mid } else { $hi = $mid - 1 }; Flush-UI }
            $mtu = $lo + 28
        }
    } finally { Hide-Overlay }
    $ci = Get-ConnInfo
    $cur = 0; try { $cur = [int](Get-NetIPInterface -InterfaceIndex $ci.Index -AddressFamily IPv4 -ErrorAction Stop).NlMtu } catch { }
    $script:MtuFound = $mtu
    $BtnMtuApply.Visibility = 'Collapsed'
    if ($mtu -eq 0) { $MtuRes.Text = 'The test could not run (ping is blocked on this connection).' }
    elseif ($mtu -ge 1500) { $MtuRes.Text = "Your connection carries full 1500-byte packets (adapter MTU $cur) - perfect, nothing to change." }
    else {
        $MtuRes.Text = "Your connection only carries packets up to $mtu bytes (typical for DSL / PPPoE or DS-Lite), but your adapter sends $cur. Setting the adapter to $mtu avoids split (fragmented) packets."
        if ($cur -gt $mtu) { $BtnMtuApply.Content = "Set MTU to $mtu"; $BtnMtuApply.Visibility = 'Visible' }
    }
    $BtnMtuReset.Visibility = $(if (@($State.misc.Keys | Where-Object { $_ -like 'mtu_*' }).Count -gt 0) { 'Visible' } else { 'Collapsed' })
    Write-Log "MTU test: path MTU $mtu, adapter $cur"
}
function Set-AdapterMtu([int]$mtu) {
    $ci = Get-ConnInfo
    $ipif = Get-NetIPInterface -InterfaceIndex $ci.Index -AddressFamily IPv4 -ErrorAction Stop
    $k = "mtu_$($ci.Index)"
    if (-not $State.misc.ContainsKey($k)) { $State.misc[$k] = [int]$ipif.NlMtu }
    Set-NetIPInterface -InterfaceIndex $ci.Index -AddressFamily IPv4 -NlMtuBytes $mtu -ErrorAction Stop
    Save-State
    Write-Log "Adapter MTU set to $mtu"
}
function Reset-AdapterMtu {
    foreach ($k in @($State.misc.Keys | Where-Object { $_ -like 'mtu_*' })) {
        $idx = [int]($k -replace 'mtu_', '')
        try { Set-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -NlMtuBytes ([int]$State.misc[$k]) -ErrorAction Stop } catch { }
        $State.misc.Remove($k)
    }
    Save-State
    Write-Log 'Adapter MTU restored'
}

# ---- network repair
function Invoke-NetQuickFix {
    $r = Show-Msg "Quick fix: flush the DNS cache, clear the ARP cache and renew your IP address.`n`nYour connection drops for a few seconds. Continue?" 'Network quick fix' 'YesNo' 'Question'
    if ([string]$r -ne 'Yes') { return }
    Show-Overlay 'Repairing the connection...'
    try {
        Clear-DnsClientCache; ipconfig /flushdns | Out-Null
        netsh interface ip delete arpcache | Out-Null
        ipconfig /release | Out-Null; Start-Sleep -Milliseconds 800; ipconfig /renew | Out-Null
        $NetFixRes.Text = "Done at $((Get-Date).ToString('HH:mm')) - DNS and ARP cache cleared, IP address renewed."
        Write-Log 'Network quick fix done'
    } catch { $NetFixRes.Text = "Quick fix failed: $($_.Exception.Message)" }
    Hide-Overlay
}
function Invoke-NetFullReset {
    $r = Show-Msg "Full network reset: resets Winsock and the TCP/IP stack to Windows defaults. This fixes broken connections caused by VPNs, old tools or malware.`n`nNOTE: a manually set (static) IP address and some VPN adapters must be set up again. A restart is required. Continue?" 'Full network reset' 'YesNo' 'Warning'
    if ([string]$r -ne 'Yes') { return }
    Show-Overlay 'Resetting the network stack...'
    try {
        netsh winsock reset | Out-Null
        netsh int ip reset | Out-Null
        netsh int ipv6 reset | Out-Null
        Clear-DnsClientCache
        $NetFixRes.Text = 'Network stack reset - restart your PC to finish.'
        Write-Log 'Full network reset done'
        Show-Reboot
    } catch { $NetFixRes.Text = "Reset failed: $($_.Exception.Message)" }
    Hide-Overlay
}

# ---- Game Network Mode: pause background downloads while a game runs
$script:GameNetSvcs = @('BITS', 'DoSvc')
function Enter-GameNetMode([switch]$Force) {
    if ($script:GameNetSaved) { return }
    if (-not $Force -and $State.misc['GameNetMode'] -ne $true) { return }
    $script:GameNetSaved = @{ Svcs = @(); OneDrive = $null }
    foreach ($n in $GameNetSvcs) {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq 'Running') { try { Stop-Service -Name $n -Force -ErrorAction Stop; $GameNetSaved.Svcs += $n } catch { } }
    }
    $od = Get-Process -Name OneDrive -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($od) { try { $GameNetSaved.OneDrive = $od.Path; Get-Process -Name OneDrive | ForEach-Object { $_.Kill() } } catch { } }
    Write-Log ("Game network mode ON: paused " + (@($GameNetSaved.Svcs) + $(if ($GameNetSaved.OneDrive) { 'OneDrive' } else { @() }) -join ', '))
}
function Exit-GameNetMode {
    if (-not $script:GameNetSaved) { return }
    foreach ($n in $GameNetSaved.Svcs) { try { Start-Service -Name $n -ErrorAction SilentlyContinue } catch { } }
    if ($GameNetSaved.OneDrive -and (Test-Path -LiteralPath $GameNetSaved.OneDrive)) {
        try { Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$($GameNetSaved.OneDrive)`"" } catch { }
    }
    Write-Log 'Game network mode OFF: background downloads resumed'
    $script:GameNetSaved = $null
}

# ------------------------------------------------------------------ UI helpers
$script:BrushCache = @{}
function Get-Brush([string]$hex) {
    if (-not $BrushCache.ContainsKey($hex)) {
        $b = ([System.Windows.Media.BrushConverter]::new()).ConvertFromString($hex)
        $b.Freeze()
        $BrushCache[$hex] = $b
    }
    $BrushCache[$hex]
}
function X([string]$s) { [System.Security.SecurityElement]::Escape($s) }
$script:NS = 'xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"'
$script:Inv = [System.Globalization.CultureInfo]::InvariantCulture

function Flush-UI { try { $Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action] { }) } catch { } }
function Show-Overlay([string]$m) { $OverlayText.Text = [SBLang]::Tr($m); $Overlay.Visibility = 'Visible'; Flush-UI }
function Hide-Overlay { $Overlay.Visibility = 'Collapsed' }
function Set-Status([string]$m, [string]$kind = 'ok') {
    if (-not $script:StatusText) { return }
    $StatusText.Text = [SBLang]::Tr($m)
    $c = '#2ED47A'
    if ($kind -eq 'busy') { $c = '#FF8A1F' } elseif ($kind -eq 'err') { $c = '#EF4444' }
    $StatusDot.Fill = Get-Brush $c
    Flush-UI
}
function Show-Msg($text, $title = 'Silvan Boost', $btn = 'OK', $icon = 'Information') {
    [System.Windows.MessageBox]::Show($Window, [SBLang]::Tr([string]$text), [SBLang]::Tr([string]$title), $btn, $icon)
}

function Set-Arc($Path, [double]$Pct, [double]$Size, [double]$Thick) {
    $p = [Math]::Max(0, [Math]::Min(99.99, $Pct))
    if ($p -lt 0.5) { $Path.Data = $null; return }
    $r = ($Size - $Thick) / 2; $c = $Size / 2
    $a = $p / 100 * 2 * [Math]::PI
    $x = $c + $r * [Math]::Sin($a); $y = $c - $r * [Math]::Cos($a)
    $large = 0; if ($p -gt 50) { $large = 1 }
    $s = [string]::Format($Inv, 'M {0},{1} A {2},{2} 0 {3} 1 {4},{5}', $c, ($c - $r), $r, $large, $x, $y)
    $Path.Data = [System.Windows.Media.Geometry]::Parse($s)
}

$script:CpuHist = New-Object System.Collections.Generic.List[double]
function Draw-Spark {
    $w = $CpuSpark.ActualWidth; $h = $CpuSpark.ActualHeight
    if ($w -le 0 -or $CpuHist.Count -lt 2) { return }
    $n = 60; $step = $w / ($n - 1); $start = $n - $CpuHist.Count
    $pts = New-Object System.Windows.Media.PointCollection
    $area = New-Object System.Windows.Media.PointCollection
    $area.Add([System.Windows.Point]::new($start * $step, $h))
    for ($i = 0; $i -lt $CpuHist.Count; $i++) {
        $pt = [System.Windows.Point]::new(($start + $i) * $step, $h - ($CpuHist[$i] / 100) * ($h - 6) - 3)
        $pts.Add($pt); $area.Add($pt)
    }
    $area.Add([System.Windows.Point]::new(($n - 1) * $step, $h))
    $CpuLine.Points = $pts
    $CpuArea.Points = $area
}

# ------------------------------------------------------------------ cards
$script:UI = @{}
$script:RiskStyle = @{
    Safe      = @('#1A2ED47A', '#5BE39A')
    Moderate  = @('#1AF59E0B', '#FBBF24')
    Advanced  = @('#1AEF4444', '#F87171')
    Permanent = @('#1AEF4444', '#F87171')
    Action    = @('#1A3B82F6', '#7AA7FF')
}

function Get-UIEntry($id) {
    if (-not $UI.ContainsKey($id)) { $UI[$id] = @{ Card = $null; Status = $null; Toggles = (New-Object System.Collections.ArrayList); FeatStatus = $null } }
    $UI[$id]
}

function New-TweakCard($t) {
    $label = $t.Risk; $key = $t.Risk
    if ($t.Permanent) { $label = 'Permanent'; $key = 'Permanent' } elseif ($t.Action) { $label = 'One-click'; $key = 'Action' }
    $rs = $RiskStyle[$key]
    $extra = ''
    if ($t.Reboot) { $extra = '<Border CornerRadius="6" Padding="7,2" Margin="6,0,0,0" Background="#1A3B82F6"><TextBlock Text="Restart" FontSize="10.5" Foreground="#7AA7FF"/></Border>' }
    if ($t.Action) { $ctrl = '<Button x:Name="Run" DockPanel.Dock="Right" Style="{DynamicResource SmallBtn}" Content="' + (X $t.Button) + '"/>' }
    else { $ctrl = '<CheckBox x:Name="Tg" DockPanel.Dock="Right" Style="{DynamicResource Toggle}" VerticalAlignment="Center"/>' }
    $xml = @"
<Border $NS Style="{DynamicResource Card}" Margin="0,0,12,12" Padding="16,14,16,12">
  <DockPanel>
    <DockPanel DockPanel.Dock="Top">
      <Border DockPanel.Dock="Right" CornerRadius="6" Padding="7,2" Background="$($rs[0])"><TextBlock Text="$label" FontSize="10.5" FontWeight="SemiBold" Foreground="$($rs[1])"/></Border>
      <StackPanel Orientation="Horizontal">
        <Border CornerRadius="6" Padding="8,2" Background="#1A2440"><TextBlock Text="$(X $t.Cat)" FontSize="10.5" Foreground="#A9B3CC"/></Border>
        $extra
      </StackPanel>
    </DockPanel>
    <Border DockPanel.Dock="Bottom" BorderBrush="#1A2440" BorderThickness="0,1,0,0" Padding="0,10,0,0" Margin="0,12,0,0">
      <DockPanel>
        $ctrl
        <TextBlock x:Name="St" Text="Inactive" FontSize="12" Foreground="#9AA5BF" VerticalAlignment="Center" TextTrimming="CharacterEllipsis" Margin="0,0,10,0"/>
      </DockPanel>
    </Border>
    <StackPanel Margin="0,12,0,0">
      <TextBlock Text="$(X $t.Name)" FontSize="15" FontWeight="SemiBold" TextWrapping="Wrap"/>
      <TextBlock Text="$(X $t.Desc)" FontSize="12.5" Foreground="#9AA5BF" TextWrapping="Wrap" Margin="0,6,0,0" LineHeight="18" MaxHeight="72" TextTrimming="CharacterEllipsis"/>
    </StackPanel>
  </DockPanel>
</Border>
"@
    $card = [System.Windows.Markup.XamlReader]::Parse($xml)
    $card.ToolTip = $t.Desc
    $u = Get-UIEntry $t.Id
    $u.Card = $card
    $u.Status = $card.FindName('St')
    if ($t.Action) {
        $b = $card.FindName('Run'); $b.Tag = $t.Id
        $b.Add_Click({ param($s, $e) try { Invoke-ActionTweak $TweakById[[string]$s.Tag] } catch { Write-Log "UI error: $_" } })
    } else {
        $tg = $card.FindName('Tg'); $tg.Tag = $t.Id
        $tg.Add_Click({ param($s, $e) try { [void](Set-TweakState $TweakById[[string]$s.Tag] ([bool]$s.IsChecked)) } catch { Write-Log "UI error: $_" } })
        [void]$u.Toggles.Add($tg)
    }
    $card
}

function New-FeatRow($t) {
    $xml = @"
<Border $NS BorderBrush="#1A2440" BorderThickness="0,1,0,0" Padding="0,11,0,11">
  <DockPanel>
    <CheckBox x:Name="Tg" DockPanel.Dock="Right" Style="{DynamicResource Toggle}" VerticalAlignment="Center" Margin="14,0,0,0"/>
    <StackPanel>
      <TextBlock Text="$(X $t.Name)" FontSize="13.5" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
      <TextBlock Text="$(X $t.Desc)" FontSize="12" Foreground="#9AA5BF" TextTrimming="CharacterEllipsis" Margin="0,2,0,0"/>
    </StackPanel>
  </DockPanel>
</Border>
"@
    $row = [System.Windows.Markup.XamlReader]::Parse($xml)
    $row.ToolTip = $t.Desc
    $tg = $row.FindName('Tg'); $tg.Tag = $t.Id
    $tg.Add_Click({ param($s, $e) try { [void](Set-TweakState $TweakById[[string]$s.Tag] ([bool]$s.IsChecked)) } catch { Write-Log "UI error: $_" } })
    [void](Get-UIEntry $t.Id).Toggles.Add($tg)
    $row
}

function New-HwCard([string]$badge, [string]$title, [string]$main, $lines) {
    $rows = ''
    foreach ($l in $lines) {
        $v = [string]$l[1]; if (-not $v) { $v = 'n/a' }
        $rows += "<DockPanel Margin=`"0,4,0,0`"><TextBlock DockPanel.Dock=`"Right`" Text=`"$(X $v)`" FontSize=`"12.5`" MaxWidth=`"210`" TextTrimming=`"CharacterEllipsis`" TextAlignment=`"Right`"/><TextBlock Text=`"$(X $l[0])`" FontSize=`"12.5`" Foreground=`"#9AA5BF`"/></DockPanel>"
    }
    if (-not $main) { $main = 'Not detected' }
    $xml = @"
<Border $NS Style="{DynamicResource Card}" Margin="0,0,12,12">
  <StackPanel>
    <StackPanel Orientation="Horizontal">
      <Border Height="30" MinWidth="40" CornerRadius="9" Padding="8,0" Background="#1FFF8A1F"><TextBlock Text="$(X $badge)" FontSize="11" FontWeight="Bold" Foreground="#FF9A3C" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
      <TextBlock Text="$(X $title)" Margin="10,0,0,0" VerticalAlignment="Center" FontSize="11" FontWeight="SemiBold" Foreground="#9AA5BF"/>
    </StackPanel>
    <TextBlock Text="$(X $main)" FontSize="16" FontWeight="SemiBold" Margin="0,12,0,6" TextWrapping="Wrap"/>
    $rows
  </StackPanel>
</Border>
"@
    [System.Windows.Markup.XamlReader]::Parse($xml)
}

function New-RecRow($rec) {
    switch ($rec.S) {
        'ok'   { $g = '&#xE73E;'; $bg = '#1F2ED47A'; $fg = '#2ED47A' }
        'warn' { $g = '&#xE7BA;'; $bg = '#1FF59E0B'; $fg = '#FBBF24' }
        default { $g = '&#xE946;'; $bg = '#1F3B82F6'; $fg = '#7AA7FF' }
    }
    $xml = @"
<Border $NS Style="{DynamicResource Card}" Padding="14" Margin="0,0,0,10">
  <DockPanel>
    <Border DockPanel.Dock="Left" Width="32" Height="32" CornerRadius="16" Background="$bg" VerticalAlignment="Top">
      <TextBlock Text="$g" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="13" Foreground="$fg" HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
    <StackPanel Margin="12,0,0,0">
      <TextBlock Text="$(X $rec.T)" FontWeight="SemiBold" FontSize="14" TextWrapping="Wrap"/>
      <TextBlock Text="$(X $rec.X)" Foreground="#9AA5BF" TextWrapping="Wrap" FontSize="12.5" Margin="0,3,0,0"/>
    </StackPanel>
  </DockPanel>
</Border>
"@
    [System.Windows.Markup.XamlReader]::Parse($xml)
}

# ------------------------------------------------------------------ UI state updates
function Update-TweakUI($t) {
    $u = $UI[$t.Id]; if (-not $u) { return }
    $avail = (-not $t.NotAvail)
    foreach ($tg in $u.Toggles) { $tg.IsChecked = [bool]$t.Active; $tg.IsEnabled = ($avail -or $t.Active) }
    if ($u.Card) {
        if ($avail) { $u.Card.Opacity = 1 } else { $u.Card.Opacity = 0.55 }
        $run = $u.Card.FindName('Run'); if ($run) { $run.IsEnabled = $avail }
    }
    if (-not $u.Status) { return }
    if ($t.NotAvail -and -not $t.Active) {
        $u.Status.Text = "Not available: $($t.NotAvail)"; $u.Status.Foreground = Get-Brush '#7F8BA6'
        $u.Status.ToolTip = $u.Status.Text
        return
    }
    if ($t.Unfit -and -not $t.Active) {
        $u.Status.Text = "Not recommended: $($t.Unfit)"; $u.Status.Foreground = Get-Brush '#FBBF24'
        $u.Status.ToolTip = $u.Status.Text
        if ($u.Card) { $u.Card.BorderBrush = Get-Brush '#1E2A45' }
        return
    }
    $u.Status.ToolTip = $null
    if ($t.Action) {
        if ($t.LastMsg) { $u.Status.Text = $t.LastMsg }
        elseif ($t.Active) { $u.Status.Text = 'Done' }
        else { $u.Status.Text = 'Ready' }
        $u.Status.Foreground = Get-Brush '#9AA5BF'
    } else {
        if ($t.Active) { $u.Status.Text = 'Active'; $u.Status.Foreground = Get-Brush '#5BE39A'; $u.Card.BorderBrush = Get-Brush '#66FF8A1F' }
        else { $u.Status.Text = 'Inactive'; $u.Status.Foreground = Get-Brush '#9AA5BF'; $u.Card.BorderBrush = Get-Brush '#1E2A45' }
    }
}

function Update-Stats {
    $toggles = @($Tweaks | Where-Object { -not $_.Action -and (-not $_.NotAvail -or $_.Active) })
    $active = @($toggles | Where-Object { $_.Active }).Count
    $total = $toggles.Count
    $score = 0; if ($total -gt 0) { $score = [math]::Round($active / $total * 100) }
    $StatActive.Text = "$active"
    try { Update-Hero $score } catch { }
    $ScoreBar.Width = [Math]::Max(0, ($ScoreBar.Parent.ActualWidth) * $score / 100)
    $TweakSub.Text = "$active of $total optimizations active - $($Tweaks.Count) tools in total, every change can be reverted."
    try { Update-NextStep } catch { }
}

function Update-BackupPage {
    if (-not $script:BackupInfo) { return }
    $n = $State.reg.Count + $State.svc.Count
    $BackupInfo.Text = "$n original Windows values are saved and can be restored.`nFile: $StateFile"
    $lr = [string]$State.misc['LastRP']
    if ($lr) { $RpInfo.Text = "Last restore point by Silvan Boost: $lr. One is created automatically before the first change of every session." }
    else { $RpInfo.Text = 'No restore point created yet. One is created automatically before the first change of every session.' }
}

function Show-Reboot { $RebootPill.Visibility = 'Visible' }

# ------------------------------------------------------------------ actions
function Set-TweakState($t, [bool]$want, [switch]$Quiet) {
    if ($want -and $t.NotAvail) {
        if (-not $Quiet) { Show-Msg "$($t.Name) is not available on this PC: $($t.NotAvail)." | Out-Null }
        Update-TweakUI $t; return $false
    }
    if ($want -and $t.Unfit -and -not $Quiet) {
        $r = Show-Msg ("$($t.Name)`n`nNot recommended for this PC: $($t.Unfit).`n`nApply it anyway?") 'Not recommended' 'YesNo' 'Warning'
        if ([string]$r -ne 'Yes') { Update-TweakUI $t; return $false }
    }
    if ($want -and $t.Risk -eq 'Advanced' -and -not $Quiet) {
        $r = Show-Msg ("$($t.Name)`n`n$($t.Desc)`n`nThis is an advanced optimization. Apply it?") 'Advanced optimization' 'YesNo' 'Warning'
        if ([string]$r -ne 'Yes') { Update-TweakUI $t; return $false }
    }
    if ($want -and -not (Ensure-RestorePoint)) { Update-TweakUI $t; return $false }
    $verb = 'Reverting'; if ($want) { $verb = 'Applying' }
    Set-Status "$verb $($t.Name)..." 'busy'
    $ok = $true
    try {
        Invoke-Tweak $t $want
        Write-Log ("{0}: {1}" -f $(if ($want) { 'Applied' } else { 'Reverted' }), $t.Name)
        if ($t.Reboot) { Show-Reboot }
    } catch {
        $ok = $false
        Write-Log "FAILED $($t.Name): $($_.Exception.Message)"
        if (-not $Quiet) { Show-Msg ("Could not change '$($t.Name)':`n`n$($_.Exception.Message)") 'Silvan Boost' 'OK' 'Error' | Out-Null }
    }
    $t.Active = Test-Tweak $t
    Update-TweakUI $t
    Update-Stats; Update-BackupPage
    if ($CatFilter -eq 'Active') { Apply-Filter }
    if ($ok) { Set-Status ("{0}: {1}" -f $t.Name, $(if ($t.Active) { 'active' } else { 'off' })) }
    else { Set-Status "Failed: $($t.Name) - see Backup & Restore > Activity log" 'err' }
    return $ok
}

function Invoke-ActionTweak($t) {
    if ($t.Permanent) {
        $r = Show-Msg ("$($t.Name)`n`n$($t.Desc)`n`nThis cannot be undone from Silvan Boost. Continue?") 'Silvan Boost' 'YesNo' 'Warning'
        if ([string]$r -ne 'Yes') { return }
    }
    Show-Overlay "$($t.Name)..."
    Set-Status "$($t.Name)..." 'busy'
    try {
        $out = @(& $t.Apply)
        $msg = 'Done'; if ($out.Count -gt 0 -and $out[-1]) { $msg = [string]$out[-1] }
        $t.LastMsg = $msg
        Write-Log "$($t.Name): $msg"
        Set-Status "$($t.Name): $msg"
    } catch {
        $t.LastMsg = 'Failed'
        Write-Log "FAILED $($t.Name): $($_.Exception.Message)"
        Set-Status "Failed: $($t.Name)" 'err'
        Show-Msg ("$($t.Name) failed:`n`n$($_.Exception.Message)") 'Silvan Boost' 'OK' 'Error' | Out-Null
    } finally { Hide-Overlay }
    $t.Active = Test-Tweak $t
    Update-TweakUI $t
}

function Invoke-Preset([string]$name) {
    if ($name -eq 'safe') {
        $list = @($Tweaks | Where-Object { -not $_.Action -and $_.Risk -eq 'Safe' -and (Test-Suitable $_) })
        $title = 'Apply recommended'
        $note = 'Applies every Safe optimization that suits this PC.'
    } else {
        $cats = @('FPS & Latency', 'Network & Ping', 'Memory & Storage', 'Registry')
        $skip = @('dns-cf', 'search-index')
        $list = @($Tweaks | Where-Object { -not $_.Action -and (Test-Suitable $_) -and ($_.Risk -eq 'Safe' -or ($_.Risk -eq 'Moderate' -and $cats -contains $_.Cat -and $skip -notcontains $_.Id)) })
        $title = 'Max performance'
        $note = 'Applies all Safe optimizations plus the Moderate performance tweaks. Tweaks that do not suit this PC and Advanced tweaks are never applied automatically.'
    }
    $todo = @($list | Where-Object { -not $_.Active })
    if ($todo.Count -eq 0) { Show-Msg 'Everything in this preset is already active.' | Out-Null; return }
    $r = Show-Msg "$note`n`n$($todo.Count) optimizations will be applied. Continue?" $title 'YesNo' 'Question'
    if ([string]$r -ne 'Yes') { return }
    if (-not (Ensure-RestorePoint)) { return }
    $fail = New-Object System.Collections.ArrayList
    $i = 0
    foreach ($t in $todo) {
        $i++
        Show-Overlay ("Applying {0} of {1}`n{2}" -f $i, $todo.Count, $t.Name)
        if (-not (Set-TweakState $t $true -Quiet)) { [void]$fail.Add($t.Name) }
    }
    Hide-Overlay
    $okCount = $todo.Count - $fail.Count
    $msg = "$okCount optimizations applied."
    if ($fail.Count -gt 0) { $msg += "`n`nSkipped (not supported on this PC):`n - " + ($fail -join "`n - ") }
    if ($RebootPill.Visibility -eq 'Visible') { $msg += "`n`nRestart your PC to finish." }
    Set-Status "$title finished: $okCount applied"
    Show-Msg $msg $title | Out-Null
}

function Invoke-RevertAll {
    $list = @($Tweaks | Where-Object { $_.Active -and -not $_.Action })
    if ($list.Count -eq 0) { Show-Msg 'No optimizations are active.' | Out-Null; return }
    $r = Show-Msg "Revert all $($list.Count) active optimizations to your original Windows settings?" 'Revert all' 'YesNo' 'Question'
    if ([string]$r -ne 'Yes') { return }
    [array]::Reverse($list)
    $i = 0
    foreach ($t in $list) {
        $i++
        Show-Overlay ("Reverting {0} of {1}`n{2}" -f $i, $list.Count, $t.Name)
        [void](Set-TweakState $t $false -Quiet)
    }
    Hide-Overlay
    Set-Status 'All optimizations reverted.'
    Show-Msg 'All optimizations were reverted. Restart your PC to finish.' | Out-Null
}

# ------------------------------------------------------------------ scanner page
$script:HW = @{}
$script:Recs = @()
function Run-Scan {
    $script:HW = Get-HW
    $script:Recs = @(Get-Recs $HW)
    $h = $HW
    $HwGrid.Children.Clear()

    $l = New-Object System.Collections.ArrayList
    [void]$l.Add(@('Cores', $h.Topology)); [void]$l.Add(@('Threads', "$($h.Threads)"))
    [void]$l.Add(@('Base clock', $h.CpuBase)); [void]$l.Add(@('L3 cache', $h.L3))
    if ($h.Microcode) { [void]$l.Add(@('Microcode', ('0x{0:X}' -f $h.Microcode))) }
    [void]$HwGrid.Children.Add((New-HwCard 'CPU' 'PROCESSOR' $h.CpuName $l))

    $l = New-Object System.Collections.ArrayList
    if ($h.VramGB) { [void]$l.Add(@('VRAM', "$($h.VramGB) GB")) }
    [void]$l.Add(@('Driver', $h.GpuDriver))
    if ($h.Pcie) { [void]$l.Add(@('PCIe link', $h.Pcie)) }
    if ($h.Bar1) { [void]$l.Add(@('Resizable BAR', $(if ($h.Bar1 -gt 1024) { 'Enabled' } else { 'Off' }))) }
    [void]$HwGrid.Children.Add((New-HwCard 'GPU' 'GRAPHICS' $h.GpuName $l))

    $l = New-Object System.Collections.ArrayList
    [void]$l.Add(@('Speed', "$($h.RamConf) MT/s"))
    [void]$l.Add(@('Modules', "$($h.RamMods) x $($h.RamModSize) GB"))
    [void]$l.Add(@('Maker', $h.RamMfr)); [void]$l.Add(@('Part', $h.RamPart))
    [void]$HwGrid.Children.Add((New-HwCard 'RAM' 'MEMORY' ("$($h.RamGB) GB $($h.RamType)") $l))

    $l = New-Object System.Collections.ArrayList
    $mainDisk = $null
    foreach ($d in $h.Disks) {
        $desc = "$($d.SizeGB) GB $($d.Bus) $($d.Type)".Replace('Unspecified', '').Trim()
        if (-not $mainDisk) { $mainDisk = $d.Name }
        [void]$l.Add(@($d.Name, $desc))
    }
    if ($h.SysSizeGB) { [void]$l.Add(@("$env:SystemDrive free", "$($h.SysFreeGB) of $($h.SysSizeGB) GB")) }
    [void]$HwGrid.Children.Add((New-HwCard 'SSD' 'STORAGE' $mainDisk $l))

    $l = New-Object System.Collections.ArrayList
    [void]$l.Add(@('Current', "$($h.RefCur) Hz")); [void]$l.Add(@('Maximum', "$($h.RefMax) Hz"))
    [void]$HwGrid.Children.Add((New-HwCard 'HZ' 'DISPLAY' ("$($h.ResW) x $($h.ResH) @ $($h.RefCur) Hz") $l))

    $l = New-Object System.Collections.ArrayList
    [void]$l.Add(@('BIOS', $h.Bios)); [void]$l.Add(@('BIOS date', $h.BiosDate))
    [void]$HwGrid.Children.Add((New-HwCard 'MB' 'MOTHERBOARD' $h.Board $l))

    $l = New-Object System.Collections.ArrayList
    [void]$l.Add(@('Version', $h.OSVer)); [void]$l.Add(@('Build', $h.OSBuild))
    [void]$HwGrid.Children.Add((New-HwCard 'OS' 'WINDOWS' $h.OS $l))

    $l = New-Object System.Collections.ArrayList
    [void]$l.Add(@('Adapter', $h.NicName)); [void]$l.Add(@('Link speed', $h.NicSpeed))
    [void]$HwGrid.Children.Add((New-HwCard 'NET' 'NETWORK' $h.Nic $l))

    $vbsTxt = 'Off'; if ($h.Vbs -eq 2) { $vbsTxt = 'Running' } elseif ($h.Vbs -eq 1) { $vbsTxt = 'Enabled' } elseif ($h.Vbs -lt 0) { $vbsTxt = 'Unknown' }
    $l = New-Object System.Collections.ArrayList
    [void]$l.Add(@('Game Mode', $(if ($h.GameMode) { 'On' } else { 'Off' })))
    [void]$l.Add(@('GPU scheduling', $(if ($h.Hags) { 'On' } else { 'Off' })))
    [void]$l.Add(@('VBS', $vbsTxt))
    [void]$HwGrid.Children.Add((New-HwCard 'FPS' 'GAMING STATUS' $h.Plan $l))

    $RecList.Children.Clear()
    foreach ($rec in ($Recs | Sort-Object { switch ($_.S) { 'warn' { 0 } 'info' { 1 } default { 2 } } })) { [void]$RecList.Children.Add((New-RecRow $rec)) }

    $ramTxt = "$($h.RamGB) GB $($h.RamType)-$($h.RamConf)"
    $HomeSub.Text = "Tuned for your $($h.CpuShort)  |  $($h.GpuShort)  |  $ramTxt"
    $TitleSpec.Text = "$($h.CpuShort)  /  $($h.GpuShort)"
    $CpuNameTxt.Text = $h.CpuName
    $kind = 'desktop PC'; if ($h.IsLaptop) { $kind = 'laptop' }
    $AboutRig.Text = "This $kind was detected as: $($h.CpuName), $($h.GpuName), $($h.RamGB) GB $($h.RamType), Windows on $(if ($h.SysIsSSD) { 'an SSD' } else { 'a hard drive' }). Silvan Boost scans the hardware every time it starts: tweaks that cannot work here are disabled, and tweaks that are a bad idea on this PC are marked and skipped by the presets."
    Update-Fit
    foreach ($t in $Tweaks) { if ($UI.ContainsKey($t.Id)) { Update-TweakUI $t } }
}

# ------------------------------------------------------------------ filtering
$script:CatFilter = 'All'
function Apply-Filter {
    $q = $SearchBox.Text.Trim()
    $n = 0
    foreach ($t in $Tweaks) {
        $ok = ($CatFilter -eq 'All') -or ($CatFilter -eq 'Active' -and $t.Active) -or ($t.Cat -eq $CatFilter)
        if ($ok -and $q) {
            $ok = ($t.Name.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or ($t.Desc.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0)
        }
        $c = $UI[$t.Id].Card
        if ($ok) { $c.Visibility = 'Visible'; $n++ } else { $c.Visibility = 'Collapsed' }
    }
    $ShowCount.Text = "Showing $n of $($Tweaks.Count)"
}

function Build-Chips {
    $cats = @('All', 'Active', 'FPS & Latency', 'Network & Ping', 'Input', 'Memory & Storage', 'Processes', 'Registry', 'Debloat', 'Privacy', 'Quality of Life')
    foreach ($c in $cats) {
        $rb = New-Object System.Windows.Controls.RadioButton
        $cnt = ''
        if ($c -ne 'All' -and $c -ne 'Active') { $cnt = "  $(@($Tweaks | Where-Object { $_.Cat -eq $c }).Count)" }
        $rb.Content = "$c$cnt"
        $rb.GroupName = 'cat'
        $rb.Style = $Window.FindResource('Chip')
        $rb.Margin = [System.Windows.Thickness]::new(0, 0, 8, 8)
        $rb.Tag = $c
        if ($c -eq 'All') { $rb.IsChecked = $true }
        $rb.Add_Checked({ param($s, $e) $script:CatFilter = [string]$s.Tag; Apply-Filter })
        [void]$ChipBar.Children.Add($rb)
    }
}

function Update-Columns {
    $w = $Window.ActualWidth - 240 - 64
    $c = [Math]::Max(2, [Math]::Min(4, [int][Math]::Floor($w / 290)))
    $TweakGrid.Columns = $c
    $HwGrid.Columns = [Math]::Min(3, $c)
    $GameGrid.Columns = $c
    if ($c -ge 3) { $AppList.Columns = 2 } else { $AppList.Columns = 1 }
    $RecGrid.Columns = [Math]::Min(3, $c)
}

function Show-Page([string]$p) {
    foreach ($n in 'Home', 'Scan', 'Quick', 'Tweaks', 'Games', 'Pro', 'Live', 'Bench', 'Ping', 'Input', 'Macros', 'Proc', 'Apps', 'Backup', 'About') {
        $el = Get-Variable -Name "Page$n" -Scope Script -ValueOnly
        if ($n -eq $p) { $el.Visibility = 'Visible'; Invoke-AnimateIn $el } else { $el.Visibility = 'Collapsed' }
    }
    if ($NavCats.Count -gt 0 -and $NavOfPage.ContainsKey($p)) { Select-NavFor $NavOfPage[$p] }
    $cr = $CrumbOfPage[$p]
    if ($cr) { $CrumbCat.Text = $cr[0]; $CrumbSep.Text = $(if ($cr[0]) { '  /  ' } else { '' }); $CrumbPage.Text = $cr[1] }
    if ($p -eq 'Quick' -and $script:Started) { Update-QuickPage }
    if ($p -eq 'Home') { Update-Stats }
    if ($p -eq 'Games' -and -not $GamesLoaded -and $script:Started) { Load-Games }
    if ($p -eq 'Apps' -and -not $AppsLoaded -and $script:Started) { Load-Apps }
    if ($p -eq 'Pro' -and -not $ProSel -and $ProChipMap.ContainsKey('valorant')) { $ProChipMap['valorant'].IsChecked = $true }
    if ($p -eq 'Proc' -and $script:Started) { Load-ProcPage }
    $Sync.PingPageOn = ($p -eq 'Ping')
    if ($p -eq 'Ping' -and $script:Started) { Open-PingPage }
    if ($p -eq 'Input' -and $script:Started) { Open-InputPage }
    if ($p -eq 'Macros' -and $script:Started) { try { Open-MacrosPage } catch { Write-Log "Macros page error: $_" } }
    elseif ($script:MacroInit) { try { Stop-KeyCapture; if ([SBMacro]::Recording) { Stop-MacroRecording } } catch { } }
    if ([SBLang]::Lang -eq 'de') { try { [void][SBLang]::Apply($Window) } catch { } }
    if ($p -eq 'Bench' -and $script:Started) { try { Update-BenchUI } catch { } }
    if ($p -eq 'Live' -and $script:Started) { try { Build-History } catch { } }
    if ($p -eq 'Live') { $LiveDot.Visibility = $(if ($LiveSession) { 'Visible' } else { 'Collapsed' }) }
}

# ------------------------------------------------------------------ live metrics
$script:Sync = [hashtable]::Synchronized(@{ Run = $true; Cpu = 0.0; Ram = 0.0; RamUsed = 0.0; RamTotal = 0.0; Gpu = -1.0; GpuTemp = -1.0; VramUsed = 0.0; VramTotal = 0.0; Smi = $null
    CoreMax = 0.0; CpuPerf = 0.0; Disk = 0.0; Watch = $null; GameKey = $null; GamePid = 0; PingAvg = -1.0; PingMax = 0.0; Loss = 0.0
    BgTop = $null; BgName = ''; BgPct = 0.0; Thermal = $false; PowerCap = $false
    PmRun = $false; PmProc = $null; PmState = 'idle'; Fps = 0.0; Low1 = 0.0; FrameMs = 0.0; StutterTotal = 0; FrameHist = @(); InputLat = 0.0; PingPageOn = $false; Gateway = $null; PgNet = @(); PgGw = @(); UpdState = 'idle'; UpdJson = $null; UpdErr = $null; ArtBusy = $false; ArtDone = $false; DevBusy = $false; DevResult = $null; DevDone = $false })
function Start-Metrics {
    $Sync.Smi = $HW.Smi
    Update-GameWatchList
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('Sync', $Sync)
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
        $i = 0
        $pings = New-Object System.Collections.ArrayList
        $pinger = New-Object System.Net.NetworkInformation.Ping
        $cores = [Environment]::ProcessorCount
        $thrMode = 0
        $pgNet = New-Object System.Collections.ArrayList
        $pgGw = New-Object System.Collections.ArrayList
        $skip = @('_total', 'idle', 'system', 'memory compression', 'registry', 'secure system', 'powershell', 'presentmon', 'nvidia-smi', 'wmiprvse')
        while ($Sync.Run) {
            $i++
            try {
                $all = @(Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ProcessorInformation -ErrorAction Stop)
                $tot = $all | Where-Object { $_.Name -eq '_Total' } | Select-Object -First 1
                $v = [double]$tot.PercentProcessorUtility
                if ($v -le 0) { $v = [double]$tot.PercentProcessorTime }
                $Sync.Cpu = [Math]::Min(100.0, $v)
                $Sync.CpuPerf = [double]$tot.PercentProcessorPerformance
                $mx = 0.0
                foreach ($c in $all) {
                    if ($c.Name -match '_Total') { continue }
                    $u = [double]$c.PercentProcessorUtility
                    if ($u -le 0) { $u = [double]$c.PercentProcessorTime }
                    if ($u -gt $mx) { $mx = $u }
                }
                $Sync.CoreMax = [Math]::Min(100.0, $mx)
            } catch {
                try { $Sync.Cpu = [double](Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average } catch { }
            }
            try {
                $os = Get-CimInstance Win32_OperatingSystem
                $t = [double]$os.TotalVisibleMemorySize; $f = [double]$os.FreePhysicalMemory
                $Sync.RamTotal = $t / 1MB; $Sync.RamUsed = ($t - $f) / 1MB; $Sync.Ram = ($t - $f) / $t * 100
            } catch { }
            try {
                $d = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction Stop
                $Sync.Disk = [Math]::Max(0.0, 100.0 - [double]$d.PercentIdleTime)
            } catch { }
            if ($Sync.Smi) {
                try {
                    $l = (& $Sync.Smi --query-gpu=utilization.gpu,temperature.gpu,memory.used,memory.total --format=csv,noheader,nounits | Select-Object -First 1) -split ','
                    $Sync.Gpu = [double]$l[0].Trim(); $Sync.GpuTemp = [double]$l[1].Trim()
                    $Sync.VramUsed = [double]$l[2].Trim() / 1024; $Sync.VramTotal = [double]$l[3].Trim() / 1024
                } catch { }
            }
            if ($Sync.Watch -and ($i % 2 -eq 0)) {
                $found = $null
                foreach ($pr in [System.Diagnostics.Process]::GetProcesses()) {
                    if ($Sync.Watch.ContainsKey($pr.ProcessName.ToLower())) { $found = $pr; break }
                }
                if ($found) { $Sync.GameKey = $found.ProcessName.ToLower(); $Sync.GamePid = $found.Id } else { $Sync.GameKey = $null; $Sync.GamePid = 0 }
            }
            $game = $Sync.GameKey
            if ($game) {
                if ($i % 2 -eq 0) {
                    try {
                        $r = $pinger.Send('1.1.1.1', 1000)
                        if ($r.Status -eq 'Success') { [void]$pings.Add([double]$r.RoundtripTime) } else { [void]$pings.Add(-1.0) }
                    } catch { [void]$pings.Add(-1.0) }
                    while ($pings.Count -gt 30) { $pings.RemoveAt(0) }
                    $ok = @($pings | Where-Object { $_ -ge 0 })
                    if ($ok.Count -gt 0) {
                        $Sync.PingAvg = ($ok | Measure-Object -Average).Average
                        $Sync.PingMax = ($ok | Measure-Object -Maximum).Maximum
                    } else { $Sync.PingAvg = 999.0; $Sync.PingMax = 999.0 }
                    $Sync.Loss = ($pings.Count - $ok.Count) / [Math]::Max(1, $pings.Count) * 100
                }
                if ($i % 5 -eq 0) {
                    try {
                        $agg = @{}
                        foreach ($q in @(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -Property Name, PercentProcessorTime -ErrorAction Stop)) {
                            $n = ([string]$q.Name -replace '#\d+$', '').ToLower()
                            if ($skip -contains $n -or $n -eq $game) { continue }
                            $agg[$n] = [double]$agg[$n] + [double]$q.PercentProcessorTime
                        }
                        $top = @($agg.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3)
                        if ($top.Count -gt 0) {
                            $parts = @($top | ForEach-Object { '{0} {1:0}%' -f $_.Key, ($_.Value / $cores) })
                            $Sync.BgTop = 'Top background apps: ' + ($parts -join ',  ')
                            $Sync.BgName = [string]$top[0].Key; $Sync.BgPct = [double]$top[0].Value / $cores
                        }
                    } catch { }
                }
                if ($Sync.Smi -and ($i % 3 -eq 0) -and $thrMode -ge 0) {
                    try {
                        $o = ''
                        if ($thrMode -le 1) {
                            $o = (& $Sync.Smi --query-gpu=clocks_event_reasons.hw_thermal_slowdown,clocks_event_reasons.sw_thermal_slowdown,clocks_event_reasons.sw_power_cap --format=csv,noheader 2>&1) | Out-String
                            if ($o -match 'Active') { $thrMode = 1 } else { $thrMode = 2 }
                        }
                        if ($thrMode -eq 2) {
                            $o = (& $Sync.Smi --query-gpu=clocks_throttle_reasons.hw_thermal_slowdown,clocks_throttle_reasons.sw_thermal_slowdown,clocks_throttle_reasons.sw_power_cap --format=csv,noheader 2>&1) | Out-String
                            if ($o -notmatch 'Active') { $thrMode = -1 }
                        }
                        if ($thrMode -gt 0) {
                            $f = $o.Trim().Split(',')
                            if ($f.Count -ge 3) {
                                $Sync.Thermal = ($f[0] -match '^\s*Active' -or $f[1] -match '^\s*Active')
                                $Sync.PowerCap = ($f[2] -match '^\s*Active')
                            }
                        }
                    } catch { $thrMode = -1 }
                }
            } else {
                if ($pings.Count -gt 0) { $pings.Clear() }
                $Sync.PingAvg = -1.0; $Sync.BgTop = $null; $Sync.BgName = ''; $Sync.BgPct = 0.0; $Sync.Thermal = $false; $Sync.PowerCap = $false
            }
            if ($Sync.PingPageOn) {
                $v = -1.0
                try { $r = $pinger.Send('1.1.1.1', 900); if ($r.Status -eq 'Success') { $v = [double]$r.RoundtripTime } } catch { }
                [void]$pgNet.Add($v); while ($pgNet.Count -gt 60) { $pgNet.RemoveAt(0) }
                $v = -1.0; $gw = $Sync.Gateway
                if ($gw) { try { $r = $pinger.Send([string]$gw, 900); if ($r.Status -eq 'Success') { $v = [double]$r.RoundtripTime } } catch { } }
                [void]$pgGw.Add($v); while ($pgGw.Count -gt 60) { $pgGw.RemoveAt(0) }
                $Sync.PgNet = $pgNet.ToArray(); $Sync.PgGw = $pgGw.ToArray()
            } elseif ($pgNet.Count -gt 0) { $pgNet.Clear(); $pgGw.Clear() }
            Start-Sleep -Milliseconds 1000
        }
    })
    $script:MetricsHandle = $ps.BeginInvoke()
    $script:Timer = New-Object System.Windows.Threading.DispatcherTimer
    $Timer.Interval = [TimeSpan]::FromSeconds(1)
    $Timer.Add_Tick({
        try { Update-Live } catch { Write-Log "Live monitor error: $_" }
        try { Update-Metrics } catch { }
        try { Update-AppJobs } catch { }
        try { Update-Bench } catch { Write-Log "Benchmark error: $_" }
        try { if ($ShowEvent -and $ShowEvent.WaitOne(0)) { Show-FromTray } } catch { }
        if ([SBLang]::Lang -eq 'de') { try { [void][SBLang]::Apply($Window) } catch { } }
        if ($Sync.DevDone) { $Sync.DevDone = $false; try { Complete-DeviceDetect } catch { Write-Log "Device detection error: $_" } }
        if ($Sync.ArtDone) { $Sync.ArtDone = $false; try { foreach ($gg in $Games) { Set-GameArt $gg } } catch { } }
        if ($Sync.UpdState -eq 'done') { $Sync.UpdState = 'handled'; try { Complete-UpdateCheck } catch { Write-Log "Update check error: $_" } }
        try {
            if ($PagePing.Visibility -eq 'Visible') { Update-PingLive }
            if ($PageInput.Visibility -eq 'Visible') { Update-InputLive }
        } catch { }
    })
    $Timer.Start()
}

function Update-Metrics {
    $c = [double]$Sync.Cpu
    $CpuHist.Add($c); while ($CpuHist.Count -gt 60) { $CpuHist.RemoveAt(0) }
    if ([double]$Sync.Gpu -ge 0) { $GpuHist.Add([double]$Sync.Gpu); while ($GpuHist.Count -gt 60) { $GpuHist.RemoveAt(0) } }
    $RamHist.Add([double]$Sync.Ram); while ($RamHist.Count -gt 60) { $RamHist.RemoveAt(0) }
    if ($PageHome.Visibility -ne 'Visible') { return }
    $CpuPct.Text = '{0:0}%' -f $c
    Show-Sparkline $CpuSpark $CpuLine $CpuArea $CpuHist
    if ($c -lt 60) { Set-StatLine $CpuStat 0 'Normal load' } elseif ($c -lt 85) { Set-StatLine $CpuStat 1 'Busy' } else { Set-StatLine $CpuStat 2 'Very high load' }
    if ([double]$Sync.Gpu -ge 0) {
        $GpuPct.Text = '{0:0}%' -f $Sync.Gpu
        Show-Sparkline $GpuSpark $GpuLine $GpuArea $GpuHist
        $GpuInfo.Text = '{0:0} {1}C  |  VRAM {2:0.0} / {3:0} GB' -f $Sync.GpuTemp, [char]176, $Sync.VramUsed, $Sync.VramTotal
        $tC = [double]$Sync.GpuTemp
        if ($tC -lt 75) { Set-StatLine $GpuStat 0 'Cool and steady' } elseif ($tC -lt 83) { Set-StatLine $GpuStat 1 'Warm' } else { Set-StatLine $GpuStat 2 'Hot - check cooling' }
    } else {
        $GpuPct.Text = 'N/A'
        $GpuInfo.Text = [string]$HW.GpuShort
        $GpuStat.Text = 'Live GPU stats need an NVIDIA driver'; $GpuStat.Foreground = Get-Brush '#7F8BA6'
    }
    $r = [double]$Sync.Ram
    $RamPct.Text = '{0:0}%' -f $r
    Show-Sparkline $RamSpark $RamLine $RamArea $RamHist
    $RamInfo.Text = '{0:0.0} / {1:0} GB in use' -f $Sync.RamUsed, $Sync.RamTotal
    if ($r -lt 70) { Set-StatLine $RamStat 0 'Plenty free' } elseif ($r -lt 88) { Set-StatLine $RamStat 1 'Getting full' } else { Set-StatLine $RamStat 2 'Almost full' }
}

# ------------------------------------------------------------------ v2 shell: navigation, motion, dashboard
$script:Ease = New-Object System.Windows.Media.Animation.CubicEase
$Ease.EasingMode = 'EaseOut'
function New-Anim([double]$to, [int]$ms, [int]$delay = 0, $from = $null) {
    $a = New-Object System.Windows.Media.Animation.DoubleAnimation
    $a.To = $to
    if ($null -ne $from) { $a.From = [double]$from }
    $a.Duration = [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds($ms))
    $a.BeginTime = [TimeSpan]::FromMilliseconds($delay)
    $a.EasingFunction = $Ease
    $a
}

function Invoke-AnimateIn($el, [double]$dy = 8, [int]$ms = 260) {
    if (-not $el) { return }
    $tt = New-Object System.Windows.Media.TranslateTransform
    $el.RenderTransform = $tt
    $el.BeginAnimation([System.Windows.UIElement]::OpacityProperty, (New-Anim 1 $ms 0 0))
    $tt.BeginAnimation([System.Windows.Media.TranslateTransform]::YProperty, (New-Anim 0 $ms 0 $dy))
}

function Invoke-Press($el, [double]$s) {
    if (-not ($el -is [System.Windows.UIElement])) { return }
    $st = $el.RenderTransform
    if (-not ($st -is [System.Windows.Media.ScaleTransform]) -or $st.IsFrozen) {
        $st = New-Object System.Windows.Media.ScaleTransform 1, 1
        $el.RenderTransformOrigin = [System.Windows.Point]::new(0.5, 0.5)
        $el.RenderTransform = $st
    }
    $st.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, (New-Anim $s 120))
    $st.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, (New-Anim $s 120))
}

# ---- sidebar accordion
$script:NavCats = @()
$script:ActiveNav = 'NavHome'
$script:NavOfPage = @{ Home = 'NavHome'; Scan = 'NavScan'; Quick = 'NavQuick'; Tweaks = 'NavTweaks'; Proc = 'NavProc'; Apps = 'NavApps'
    Games = 'NavGames'; Pro = 'NavPro'; Live = 'NavLive'; Bench = 'NavBench'; Ping = 'NavPing'; Input = 'NavInput'; Macros = 'NavMacros'; Backup = 'NavBackup'; About = 'NavAbout' }
$script:CrumbOfPage = @{ Home = @('', 'Dashboard'); Scan = @('', 'PC Scan'); Quick = @('Optimize', 'Quick Boost'); Tweaks = @('Optimize', 'All Optimizations')
    Proc = @('Optimize', 'Processes'); Apps = @('Optimize', 'Apps'); Games = @('Gaming', 'Game Presets'); Pro = @('Gaming', 'Pro Settings')
    Live = @('Gaming', 'Live Monitor'); Bench = @('Gaming', 'Benchmark'); Ping = @('Network & Input', 'Ping Booster'); Input = @('Network & Input', 'Input Lag'); Macros = @('Network & Input', 'Macros')
    Backup = @('System', 'Backup & Restore'); About = @('System', 'Updates & About') }

function Initialize-NavCats {
    $script:NavCats = @(
        @{ Btn = $CatOpt; Sub = $SubOpt; Items = $SubOptItems; Chev = $CatOptChev; Dot = $CatOptDot; Navs = @('NavQuick', 'NavTweaks', 'NavProc', 'NavApps'); Open = $false },
        @{ Btn = $CatGame; Sub = $SubGame; Items = $SubGameItems; Chev = $CatGameChev; Dot = $CatGameDot; Navs = @('NavGames', 'NavPro', 'NavLive', 'NavBench'); Open = $false },
        @{ Btn = $CatNet; Sub = $SubNet; Items = $SubNetItems; Chev = $CatNetChev; Dot = $CatNetDot; Navs = @('NavPing', 'NavInput', 'NavMacros'); Open = $false },
        @{ Btn = $CatSys; Sub = $SubSys; Items = $SubSysItems; Chev = $CatSysChev; Dot = $CatSysDot; Navs = @('NavBackup', 'NavAbout'); Open = $false }
    )
    foreach ($c in $NavCats) {
        $c.Btn.Tag = $c
        $c.Btn.Add_Click({ param($s, $e) try { Switch-NavCat $s.Tag } catch { } })
    }
}

function Set-NavCatOpen($c, [bool]$open) {
    if ($c.Open -eq $open) { return }
    $c.Open = $open
    $h = 0.0; if ($open) { $h = $c.Navs.Count * 34 + 6 }
    $c.Sub.BeginAnimation([System.Windows.FrameworkElement]::HeightProperty, (New-Anim $h 260))
    $c.Sub.BeginAnimation([System.Windows.UIElement]::OpacityProperty, (New-Anim $(if ($open) { 1 } else { 0 }) 200))
    $c.Chev.RenderTransform.BeginAnimation([System.Windows.Media.RotateTransform]::AngleProperty, (New-Anim $(if ($open) { 90 } else { 0 }) 220))
    if ($open) {
        $i = 0
        foreach ($ch in $c.Items.Children) {
            $ch.BeginAnimation([System.Windows.UIElement]::OpacityProperty, (New-Anim 1 200 (60 + 35 * $i) 0))
            $i++
        }
    }
}

function Update-NavDots {
    foreach ($c in $NavCats) {
        $c.Dot.Visibility = $(if (-not $c.Open -and $c.Navs -contains $ActiveNav) { 'Visible' } else { 'Collapsed' })
    }
}

function Switch-NavCat($c) {
    if ($c.Open) { Set-NavCatOpen $c $false }
    else {
        foreach ($o in $NavCats) { if ($o -ne $c) { Set-NavCatOpen $o $false } }
        Set-NavCatOpen $c $true
    }
    Update-NavDots
}

function Select-NavFor([string]$navName) {
    $script:ActiveNav = $navName
    foreach ($c in $NavCats) { Set-NavCatOpen $c ($c.Navs -contains $navName) }
    Update-NavDots
}

# ---- dashboard
$script:GpuHist = New-Object System.Collections.Generic.List[double]
$script:RamHist = New-Object System.Collections.Generic.List[double]
$script:HeroVal = 0.0
$script:HeroTarget = -1.0

function Show-Sparkline($canvas, $line, $area, $hist) {
    $w = $canvas.ActualWidth; $h = $canvas.ActualHeight
    if ($w -le 0 -or $hist.Count -lt 2) { return }
    $n = 60; $step = $w / ($n - 1); $start = $n - $hist.Count
    $pts = New-Object System.Windows.Media.PointCollection
    $poly = New-Object System.Windows.Media.PointCollection
    $poly.Add([System.Windows.Point]::new($start * $step, $h))
    for ($i = 0; $i -lt $hist.Count; $i++) {
        $pt = [System.Windows.Point]::new(($start + $i) * $step, $h - ([Math]::Min(100, $hist[$i]) / 100) * ($h - 6) - 3)
        $pts.Add($pt); $poly.Add($pt)
    }
    $poly.Add([System.Windows.Point]::new(($n - 1) * $step, $h))
    $line.Points = $pts
    $area.Points = $poly
}

function Set-StatLine($tb, [int]$level, [string]$text) {
    $tb.Text = $text
    $tb.Foreground = Get-Brush $(switch ($level) { 0 { '#5BE39A' } 1 { '#FBBF24' } default { '#F87171' } })
}

function Start-HeroAnimation([double]$target) {
    if ($script:HeroTimer) { $HeroTimer.Stop() }
    $script:HeroAnim = @{ From = $HeroVal; To = $target; Start = Get-Date }
    $script:HeroTimer = New-Object System.Windows.Threading.DispatcherTimer
    $HeroTimer.Interval = [TimeSpan]::FromMilliseconds(16)
    $HeroTimer.Add_Tick({
            try {
                $t = ((Get-Date) - $HeroAnim.Start).TotalMilliseconds / 1000.0
                if ($t -ge 1) { $t = 1 }
                $e = 1 - [Math]::Pow(1 - $t, 3)
                $v = $HeroAnim.From + ($HeroAnim.To - $HeroAnim.From) * $e
                $script:HeroVal = $v
                Set-Arc $HeroArc $v 184 12
                $StatScore.Text = ('{0:0}%' -f $v)
                if ($t -ge 1) { $HeroTimer.Stop() }
            } catch { $HeroTimer.Stop() }
        })
    $HeroTimer.Start()
}

function Update-Hero([int]$score) {
    if ($score -ne $HeroTarget) { $script:HeroTarget = $score; Start-HeroAnimation $score }
    if ($score -ge 95) { $HeroTitle.Text = 'Your PC is fully optimized' } else { $HeroTitle.Text = "Your PC is $score% optimized" }
    $more = @(Get-QbList 'safe' | Where-Object { -not $_.Active }).Count
    if ($more -gt 0) { $HeroText.Text = "Quick Boost turns on $more more safe optimizations - it takes about 20 seconds and can be undone." }
    else { $HeroText.Text = 'All safe optimizations are on. Try the Competitive preset or the Network & Input tools for even lower latency.' }
}

$script:NextAction = 'scan'
function Update-NextStep {
    $warn = @($script:Recs | Where-Object { $_.S -eq 'warn' })
    $StatRecs.Text = "$($warn.Count)"
    $RecBadge.Visibility = $(if ($warn.Count -gt 0) { 'Visible' } else { 'Collapsed' })
    $BtnNextGo.Visibility = 'Visible'
    if ($warn.Count -gt 0) {
        $NextTitle.Text = $warn[0].T; $NextText.Text = $warn[0].X
        $NextIcon.Background = Get-Brush '#1FF59E0B'; $NextGlyph.Text = [string][char]0xE7BA; $NextGlyph.Foreground = Get-Brush '#FBBF24'
        $BtnNextGo.Content = 'Show me'; $script:NextAction = 'scan'
        return
    }
    $more = @(Get-QbList 'comp' | Where-Object { -not $_.Active }).Count
    if ($more -gt 0) {
        $NextTitle.Text = 'Tune this PC for competitive play'
        $NextText.Text = "Your hardware looks healthy. The Competitive preset turns on $more more optimizations for lower input lag and ping."
        $NextIcon.Background = Get-Brush '#26FF8A1F'; $NextGlyph.Text = [string][char]0xE945; $NextGlyph.Foreground = Get-Brush '#FFA24A'
        $BtnNextGo.Content = 'Open Quick Boost'; $script:NextAction = 'quick'
    } else {
        $NextTitle.Text = 'Everything looks great'
        $NextText.Text = 'Your hardware is healthy and all recommended optimizations are on. Enjoy the game.'
        $NextIcon.Background = Get-Brush '#1F2ED47A'; $NextGlyph.Text = [string][char]0xE73E; $NextGlyph.Foreground = Get-Brush '#5BE39A'
        $BtnNextGo.Visibility = 'Collapsed'
    }
}

function Set-UserCard {
    $u = [string]$env:USERNAME
    if (-not $u) { $u = 'User' }
    $UserName.Text = $u
    $UserInitial.Text = $u.Substring(0, 1).ToUpper()
    $dot = [string][char]0x00B7
    $os = [string]$HW.OS; if (-not $os) { $os = 'Windows' }
    $ver = ''; if ($HW.OSVer) { $ver = " $dot $($HW.OSVer)" }
    $build = ''; if ($HW.OSBuild) { $build = " (Build $($HW.OSBuild))" }
    $UserOs.Text = "$os$ver$build"
    $hr = (Get-Date).Hour
    $greet = 'Good evening'; if ($hr -lt 12) { $greet = 'Good morning' } elseif ($hr -lt 18) { $greet = 'Good afternoon' }
    $HomeGreet.Text = "$greet, $u"
}

# ---- Quick Boost page
$script:QbSel = 'comp'
$script:QbNames = @{ safe = 'Safe'; comp = 'Competitive'; max = 'Maximum' }
function Get-QbList([string]$k) {
    $l = @()
    switch ($k) {
        'safe' { $l = @($Tweaks | Where-Object { $_.Risk -eq 'Safe' }) }
        'comp' { $l = @(@($PresetComp + $PingBoostIds + $InputIds) | Select-Object -Unique | ForEach-Object { $TweakById[$_] } | Where-Object { $_ }) }
        'max' {
            $cats = @('FPS & Latency', 'Network & Ping', 'Input', 'Memory & Storage', 'Registry', 'Processes')
            $skip = @('dns-cf', 'search-index', 'print-spooler')
            $l = @($Tweaks | Where-Object { $_.Risk -eq 'Safe' -or ($_.Risk -eq 'Moderate' -and $cats -contains $_.Cat -and $skip -notcontains $_.Id) })
        }
    }
    @($l | Where-Object { -not $_.Action -and $_.Risk -ne 'Advanced' -and (Test-Suitable $_) })
}

function Update-QuickPage {
    foreach ($k in 'safe', 'comp', 'max') {
        $l = @(Get-QbList $k)
        $on = @($l | Where-Object { $_.Active }).Count
        $tb = @{ safe = $QbSafeCount; comp = $QbCompCount; max = $QbMaxCount }[$k]
        $tb.Text = "$on of $($l.Count) optimizations active"
        $tb.Foreground = Get-Brush $(if ($on -ge $l.Count -and $l.Count -gt 0) { '#5BE39A' } else { '#9AA5BF' })
    }
    $name = $QbNames[$QbSel]
    $todo = @(Get-QbList $QbSel | Where-Object { -not $_.Active })
    if ($todo.Count -eq 0) { $BtnQbApply.Content = "$name is fully applied"; $BtnQbApply.IsEnabled = $false }
    else { $BtnQbApply.Content = "Apply $name ($($todo.Count))"; $BtnQbApply.IsEnabled = $true }
    $QbList.Children.Clear()
    $head = New-Object System.Windows.Controls.TextBlock
    $head.Text = $(if ($todo.Count -eq 0) { 'Nothing left to change - everything in this preset is already active.' } else { "These $($todo.Count) optimizations will be turned on:" })
    $head.Foreground = Get-Brush '#9AA5BF'; $head.FontSize = 12.5; $head.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
    [void]$QbList.Children.Add($head)
    foreach ($t in ($todo | Select-Object -First 12)) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = [string][char]0x2022 + '  ' + $t.Name
        $tb.FontSize = 13; $tb.Margin = [System.Windows.Thickness]::new(4, 2, 0, 2)
        [void]$QbList.Children.Add($tb)
    }
    if ($todo.Count -gt 12) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = "and $($todo.Count - 12) more"; $tb.Foreground = Get-Brush '#7F8BA6'; $tb.Margin = [System.Windows.Thickness]::new(4, 4, 0, 0)
        [void]$QbList.Children.Add($tb)
    }
}

function Invoke-QuickApply {
    $name = $QbNames[$QbSel]
    $ids = @(Get-QbList $QbSel | Where-Object { -not $_.Active } | ForEach-Object { $_.Id })
    if ($ids.Count -eq 0) { return }
    $res = Invoke-TweakList "Quick Boost - $name" $ids "Apply the $name preset? These optimizations will be turned on:"
    if (-not $res.Run) { return }
    $msg = "$name applied - $($res.Applied) optimizations turned on."
    if (@($res.Failed).Count -gt 0) { $msg += " $(@($res.Failed).Count) skipped (not supported here)." }
    if ($RebootPill.Visibility -eq 'Visible') { $msg += ' Restart your PC to finish.' }
    $QbDone.Text = $msg; $QbDone.Visibility = 'Visible'; Invoke-AnimateIn $QbDone 6 220
    Update-QuickPage; Update-Stats
    Set-Status $msg
}

# ------------------------------------------------------------------ macros (mouse + keyboard)
$script:MacroCfg = $null
$script:MacroInit = $false
$script:MacroSel = 'MOUSE_MIDDLE'
$script:MacroProfileId = 'desktop'
$script:MacroActiveId = 'desktop'
$script:MacroPendingHk = $null
$script:MacroLastFg = ''
$script:MacroGame = $false
$script:CaptureMode = $null
$script:Ed = @{ Vk = 0; Vks = @(); MacroId = ''; Media = 'playpause'; Speed = 4 }
$script:MacSelId = $null
$script:MacroTimer = $null
$script:RecTimer = $null
$script:MouseTriggers = @('MOUSE_MIDDLE', 'MOUSE_BACK', 'MOUSE_FORWARD')
$script:TriggerNames = @{ MOUSE_MIDDLE = 'Middle button'; MOUSE_BACK = 'Back (side)'; MOUSE_FORWARD = 'Forward (side)' }
$script:MediaNames = @{ playpause = 'Play / Pause'; next = 'Next track'; prev = 'Previous track'; stop = 'Stop'; volup = 'Volume +'; voldown = 'Volume -'; mute = 'Mute' }
$script:SimpleKinds = @('remap', 'sniper', 'disable')

function Get-MacroCfg {
    $m = $State.misc['Macro']
    if (-not ($m -is [hashtable])) { $m = @{}; $State.misc['Macro'] = $m }
    if ($null -eq $m['Enabled']) { $m['Enabled'] = $true }
    if ($null -eq $m['Auto']) { $m['Auto'] = $true }
    $profs = @(@($m['Profiles']) | Where-Object { $_ -is [hashtable] -and $_['Id'] })
    if (-not @($profs | Where-Object { $_['Id'] -eq 'desktop' })) {
        $profs = @(@{ Id = 'desktop'; Name = 'Desktop'; Exe = ''; Game = $false; Bind = @{} }) + $profs
    }
    foreach ($p in $profs) { if (-not ($p['Bind'] -is [hashtable])) { $p['Bind'] = @{} } }
    $m['Profiles'] = $profs
    $m['Macros'] = @(@($m['Macros']) | Where-Object { $_ -is [hashtable] -and $_['Id'] })
    foreach ($mc in $m['Macros']) { $mc['Steps'] = @(@($mc['Steps']) | Where-Object { $_ -is [hashtable] }) }
    $m
}

function Get-MacroProfile([string]$id) { @($MacroCfg.Profiles | Where-Object { $_.Id -eq $id })[0] }
function Get-MacroById([string]$id) { if (-not $id) { return $null }; @($MacroCfg.Macros | Where-Object { $_.Id -eq $id })[0] }

# ---- names
$script:VkPretty = @{ 0x01 = 'Left click'; 0x02 = 'Right click'; 0x04 = 'Middle click'; 0x05 = 'Mouse back'; 0x06 = 'Mouse forward'
    0x08 = 'Backspace'; 0x09 = 'Tab'; 0x0D = 'Enter'; 0x10 = 'Shift'; 0x11 = 'Ctrl'; 0x12 = 'Alt'; 0x13 = 'Pause'; 0x14 = 'Caps Lock'; 0x1B = 'Esc'
    0x20 = 'Space'; 0x21 = 'Page Up'; 0x22 = 'Page Down'; 0x23 = 'End'; 0x24 = 'Home'; 0x25 = 'Left'; 0x26 = 'Up'; 0x27 = 'Right'; 0x28 = 'Down'
    0x2C = 'Print'; 0x2D = 'Insert'; 0x2E = 'Delete'; 0x5B = 'Win'; 0x5C = 'Win'; 0x5D = 'Menu'
    0x6A = 'Num *'; 0x6B = 'Num +'; 0x6D = 'Num -'; 0x6E = 'Num ,'; 0x6F = 'Num /'; 0x90 = 'Num Lock'; 0x91 = 'Scroll Lock'
    0xA0 = 'Left Shift'; 0xA1 = 'Right Shift'; 0xA2 = 'Left Ctrl'; 0xA3 = 'Right Ctrl'; 0xA4 = 'Left Alt'; 0xA5 = 'Right Alt'
    0xAD = 'Mute'; 0xAE = 'Volume -'; 0xAF = 'Volume +'; 0xB0 = 'Next track'; 0xB1 = 'Previous track'; 0xB2 = 'Stop'; 0xB3 = 'Play / Pause' }

function Get-VkName([int]$vk) {
    if ($VkPretty.ContainsKey($vk)) { return $VkPretty[$vk] }
    if ($vk -ge 0x30 -and $vk -le 0x39) { return [string][char]$vk }
    if ($vk -ge 0x41 -and $vk -le 0x5A) { return [string][char]$vk }
    if ($vk -ge 0x60 -and $vk -le 0x69) { return "Num $($vk - 0x60)" }
    if ($vk -ge 0x70 -and $vk -le 0x87) { return "F$($vk - 0x6F)" }
    # OEM keys: ask Windows for the label of the current layout
    try {
        $c = [SBKeyName]::Char($vk)
        if ($c -gt 32) { return ([string][char]$c).ToUpper() }
    } catch { }
    try { return [string][System.Windows.Input.KeyInterop]::KeyFromVirtualKey($vk) } catch { return "Key $vk" }
}

function Get-TriggerName([string]$trig) {
    if ($TriggerNames.ContainsKey($trig)) { return $TriggerNames[$trig] }
    if ($trig -match '^KEY:([A-Z+]*):(\d+)$') {
        $parts = @()
        foreach ($mm in ($Matches[1] -split '\+')) {
            if ($mm -eq 'CTRL') { $parts += 'Ctrl' } elseif ($mm -eq 'ALT') { $parts += 'Alt' } elseif ($mm -eq 'SHIFT') { $parts += 'Shift' } elseif ($mm -eq 'WIN') { $parts += 'Win' }
        }
        $parts += (Get-VkName ([int]$Matches[2]))
        return ($parts -join ' + ')
    }
    $trig
}

function Get-ActionText($b) {
    if (-not $b) { return 'Default' }
    switch ([string]$b.Kind) {
        'remap' { return "Key: $(Get-VkName ([int]$b.Vk))" }
        'combo' { return (@(@($b.Vks) | ForEach-Object { Get-VkName ([int]$_) }) -join ' + ') }
        'text' { $t = ([string]$b.Text) -replace '\s+', ' '; if ($t.Length -gt 22) { $t = $t.Substring(0, 22) + '...' }; return "Type `"$t`"" }
        'macro' { $mc = Get-MacroById ([string]$b.MacroId); if ($mc) { return "Macro: $($mc.Name)" } else { return 'Macro (deleted)' } }
        'run' { $p = [string]$b.Path; if ($p -notmatch '^https?://') { $p = [IO.Path]::GetFileName($p) } else { $p = ($p -replace '^https?://(www\.)?', '').TrimEnd('/') }; return "Open $p" }
        'media' { return [string]$MediaNames[[string]$b.Media] }
        'sniper' { return "Sniper mode ($([int]$b.Speed))" }
        'disable' { return 'Disabled' }
    }
    'Default'
}

# ---- engine
function ConvertTo-SBSteps($steps) {
    $l = New-Object 'System.Collections.Generic.List[SBStep]'
    foreach ($s in @($steps)) {
        if (-not ($s -is [hashtable])) { continue }
        $x = New-Object SBStep
        $x.Type = [string]$s.Type; $x.Vk = [int]$s.Vk; $x.Button = [int]$s.Button; $x.Ms = [int]$s.Ms; $x.Text = [string]$s.Text
        $l.Add($x)
    }
    , $l.ToArray()
}

function ConvertTo-SBBinding([string]$trig, $b) {
    if (-not ($b -is [hashtable]) -or -not $b.Kind) { return $null }
    $o = New-Object SBBinding
    $o.Trigger = $trig; $o.Kind = [string]$b.Kind
    $o.Vk = [int]$b.Vk; $o.Text = [string]$b.Text; $o.Path = [string]$b.Path; $o.Media = [string]$b.Media
    if ($b.Speed) { $o.Speed = [int]$b.Speed }
    if ($b.Vks) { $o.Vks = [int[]]@(@($b.Vks) | ForEach-Object { [int]$_ }) }
    if ($o.Kind -eq 'macro') {
        $mc = Get-MacroById ([string]$b.MacroId)
        if (-not $mc -or @($mc.Steps).Count -eq 0) { return $null }
        $o.Steps = ConvertTo-SBSteps $mc.Steps
        $o.Repeat = $(if ($mc.Repeat) { [string]$mc.Repeat } else { 'once' })
    }
    $o
}

function Update-MacroEngine {
    if (-not $MacroCfg) { return }
    $p = Get-MacroProfile $MacroActiveId
    if (-not $p) { $script:MacroActiveId = 'desktop'; $p = Get-MacroProfile 'desktop' }
    $list = New-Object 'System.Collections.Generic.List[SBBinding]'
    foreach ($k in @($p.Bind.Keys)) {
        $b = ConvertTo-SBBinding $k $p.Bind[$k]
        if (-not $b) { continue }
        if (($p.Game -or $MacroGame) -and -not $b.IsSimple) { continue }   # games: only 1:1 actions
        $list.Add($b)
    }
    [SBMacro]::Enabled = [bool]$MacroCfg.Enabled
    [SBMacro]::SetBindings($list.ToArray())
    # hooks only run when they are needed - no extra input processing otherwise
    if ([SBMacro]::Recording -or ($MacroCfg.Enabled -and $list.Count -gt 0)) { [SBMacro]::Start() } else { [SBMacro]::Stop() }
    Update-MacroActiveTxt
}

function Update-MacroActiveTxt {
    if (-not $script:MacroActiveTxt) { return }
    $p = Get-MacroProfile $MacroActiveId
    $t = "Active now: $($p.Name)"
    if ($MacroGame) { $t += '  -  game safe mode' }
    if (-not $MacroCfg.Enabled) { $t = 'Macros are switched off.' }
    elseif ([SBMacro]::LastError) { $t = [SBMacro]::LastError }
    $MacroActiveTxt.Text = $t
    $MacroActiveTxt.Foreground = Get-Brush $(if ([SBMacro]::LastError) { '#F87171' } elseif ($MacroCfg.Enabled) { '#5BE39A' } else { '#7F8BA6' })
    if ($script:ProfileList) {
        foreach ($rb in $ProfileList.Children) { $d = $rb.Content.FindName('ActDot'); if ($d) { $d.Visibility = $(if ($rb.Tag -eq $MacroActiveId -and $MacroCfg.Enabled) { 'Visible' } else { 'Hidden' }) } }
    }
}

function Update-MacroProfile {
    if (-not $MacroCfg) { return }
    $fg = [SBMacro]::ForegroundExe()
    if (-not $fg -or $fg -eq 'lockapp' -or [SBMacro]::OwnForeground) { return }   # keep the current profile while Silvan Boost itself is in front
    $target = 'desktop'
    if ($MacroCfg.Auto) {
        foreach ($p in $MacroCfg.Profiles) { if ($p.Exe -and $p.Exe -eq $fg) { $target = $p.Id; break } }
    } else { $target = $MacroProfileId }
    $tp = Get-MacroProfile $target
    $gm = [bool]$tp.Game -or [bool]($Sync.Watch -and $Sync.Watch.ContainsKey($fg))
    $changed = $false
    if ($gm -ne $MacroGame) { $script:MacroGame = $gm; [SBMacro]::GameMode = $gm; $changed = $true }
    if ($target -ne $MacroActiveId) { $script:MacroActiveId = $target; $changed = $true; Write-Log "Macro profile: $($tp.Name)" }
    if ($changed) { Update-MacroEngine }
}

function Initialize-Macros {
    $script:MacroCfg = Get-MacroCfg
    [SBMacro]::GameMode = $false
    Update-MacroEngine
    $script:MacroTimer = New-Object System.Windows.Threading.DispatcherTimer
    $MacroTimer.Interval = [TimeSpan]::FromMilliseconds(400)
    $MacroTimer.Add_Tick({ try { Update-MacroProfile } catch { } })
    $MacroTimer.Start()
}

function Save-Macros { Save-State; Update-MacroEngine }

# ---- page
function Open-MacrosPage {
    if (-not $MacroCfg) { return }
    if (-not $MacroInit) {
        $script:MacroInit = $true
        $MacroEnabledTg.IsChecked = [bool]$MacroCfg.Enabled
        $MacroAutoTg.IsChecked = [bool]$MacroCfg.Auto
        Build-ProfileList
        Select-MacroTrigger 'MOUSE_MIDDLE'
        Start-DeviceDetect
    }
    Show-MacroMain
    Update-MacroActiveTxt
}

function Show-MacroMain { $MacroRecView.Visibility = 'Collapsed'; $MacroMainView.Visibility = 'Visible'; Refresh-MacroProfileUI }
function Show-MacroRec {
    $MacroMainView.Visibility = 'Collapsed'; $MacroRecView.Visibility = 'Visible'; Invoke-AnimateIn $MacroRecView 8 240
    Build-MacroList
    if (-not $MacSelId -or -not (Get-MacroById $MacSelId)) { $script:MacSelId = $(if (@($MacroCfg.Macros).Count -gt 0) { $MacroCfg.Macros[0].Id } else { $null }) }
    Select-Macro $MacSelId
}

function Build-ProfileList {
    $ProfileList.Children.Clear()
    foreach ($p in $MacroCfg.Profiles) {
        $sub = $(if ($p.Exe) { "$($p.Exe).exe" } else { 'Everywhere else' })
        $pill = ''
        if ($p.Game) { $pill = '<Border DockPanel.Dock="Right" CornerRadius="6" Background="#26F59E0B" Padding="6,1" Margin="6,0,0,0" VerticalAlignment="Center"><TextBlock Text="Game" FontSize="10.5" Foreground="#FBBF24"/></Border>' }
        $x = @"
<DockPanel $NS>
  <Ellipse x:Name="ActDot" DockPanel.Dock="Right" Width="7" Height="7" Fill="#2ED47A" VerticalAlignment="Center" Margin="8,0,0,0" Visibility="Hidden" ToolTip="Active right now"/>
  $pill
  <StackPanel>
    <TextBlock Text="$(X $p.Name)" FontSize="13" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
    <TextBlock Text="$(X $sub)" FontSize="11" Foreground="#7F8BA6" TextTrimming="CharacterEllipsis"/>
  </StackPanel>
</DockPanel>
"@
        $rb = New-Object System.Windows.Controls.RadioButton
        $rb.Style = $Window.FindResource('ListRow')
        $rb.GroupName = 'macprof'
        $rb.Content = [System.Windows.Markup.XamlReader]::Parse($x)
        $rb.Tag = $p.Id
        if ($p.Id -eq $MacroProfileId) { $rb.IsChecked = $true }
        $rb.Add_Checked({ param($s, $e) try { $script:MacroProfileId = [string]$s.Tag; $script:MacroPendingHk = $null; Refresh-MacroProfileUI; Select-MacroTrigger 'MOUSE_MIDDLE'; if (-not $MacroCfg.Auto) { Update-MacroProfile } } catch { Write-Log "Macro UI error: $_" } })
        [void]$ProfileList.Children.Add($rb)
    }
    $BtnDelProfile.IsEnabled = ($MacroProfileId -ne 'desktop')
    Update-MacroActiveTxt
}

function Refresh-MacroProfileUI {
    $p = Get-MacroProfile $MacroProfileId
    if (-not $p) { $script:MacroProfileId = 'desktop'; $p = Get-MacroProfile 'desktop' }
    $MapProfileTxt.Text = "Profile: $($p.Name)"
    $BtnDelProfile.IsEnabled = ($MacroProfileId -ne 'desktop')
    Build-MacroMap
    Build-HotkeyList
}

function Build-MacroMap {
    $p = Get-MacroProfile $MacroProfileId
    $pairs = @(@('MOUSE_MIDDLE', $HsMid, $MapMidTxt), @('MOUSE_BACK', $HsBack, $MapBackTxt), @('MOUSE_FORWARD', $HsFwd, $MapFwdTxt))
    foreach ($pr in $pairs) {
        $b = $p.Bind[$pr[0]]
        $pr[2].Text = Get-ActionText $b
        $pr[2].Foreground = Get-Brush $(if ($b) { '#FFA24A' } else { '#9AA5BF' })
        $c = '#24304A'
        if ($b) { $c = '#FF8A1F' }
        if ($MacroSel -eq $pr[0]) { $c = $(if ($b) { '#FFB061' } else { '#2ED47A' }) }
        $pr[1].Background = Get-Brush $c
    }
}

function Build-HotkeyList {
    $HotkeyList.Children.Clear()
    $p = Get-MacroProfile $MacroProfileId
    $keys = @(@($p.Bind.Keys) | Where-Object { $_ -like 'KEY:*' } | Sort-Object)
    if ($MacroPendingHk -and $keys -notcontains $MacroPendingHk) { $keys += $MacroPendingHk }
    if ($keys.Count -eq 0) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = 'No hotkeys yet. Click "+ Add hotkey" and press a key or combination, e.g. F13 or Ctrl + Alt + M.'
        $tb.FontSize = 12; $tb.Foreground = Get-Brush '#7F8BA6'; $tb.TextWrapping = 'Wrap'
        [void]$HotkeyList.Children.Add($tb)
        return
    }
    foreach ($k in $keys) {
        $b = $p.Bind[$k]
        $sel = ($k -eq $MacroSel)
        $bd = $(if ($sel) { '#FF8A1F' } else { '#22304D' })
        $x = @"
<Button $NS Cursor="Hand" Margin="0,0,0,6" Background="Transparent">
  <Button.Template>
    <ControlTemplate TargetType="Button">
      <Border x:Name="Bd" CornerRadius="10" Background="#0E1628" BorderBrush="$bd" BorderThickness="1" Padding="12,8">
        <ContentPresenter/>
      </Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#141E36"/></Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate>
  </Button.Template>
  <DockPanel>
    <TextBlock DockPanel.Dock="Right" Text="$(X (Get-ActionText $b))" FontSize="12" Foreground="$(if ($b) { '#FFA24A' } else { '#7F8BA6' })" VerticalAlignment="Center" MaxWidth="200" TextTrimming="CharacterEllipsis"/>
    <Border CornerRadius="6" Background="#1A2540" BorderBrush="#2A3858" BorderThickness="1" Padding="8,3" HorizontalAlignment="Left">
      <TextBlock Text="$(X (Get-TriggerName $k))" FontSize="12" FontWeight="SemiBold" Foreground="#E8ECF5"/>
    </Border>
  </DockPanel>
</Button>
"@
        $btn = [System.Windows.Markup.XamlReader]::Parse($x)
        $btn.Tag = $k
        $btn.Add_Click({ param($s, $e) try { Select-MacroTrigger ([string]$s.Tag) } catch { Write-Log "Macro UI error: $_" } })
        [void]$HotkeyList.Children.Add($btn)
    }
}

# ---- editor
function Set-EdKind([string]$kind) {
    $map = @{ remap = $OptRemap; combo = $OptCombo; text = $OptText; macro = $OptMacro; run = $OptRun; media = $OptMedia; sniper = $OptSniper; disable = $OptDisable }
    if (-not $map.ContainsKey($kind)) { $kind = 'remap' }
    $map[$kind].IsChecked = $true
    Show-EdField $kind
}

function Get-EdKind {
    foreach ($o in @($OptRemap, $OptCombo, $OptText, $OptMacro, $OptRun, $OptMedia, $OptSniper, $OptDisable)) { if ($o.IsChecked) { return [string]$o.Tag } }
    'remap'
}

function Show-EdField([string]$kind) {
    $fields = @{ remap = $FRemap; combo = $FCombo; text = $FText; macro = $FMacro; run = $FRun; media = $FMedia; sniper = $FSniper; disable = $FDisable }
    foreach ($k in $fields.Keys) {
        if ($k -eq $kind) { $fields[$k].Visibility = 'Visible'; Invoke-AnimateIn $fields[$k] 4 180 } else { $fields[$k].Visibility = 'Collapsed' }
    }
    if ($kind -eq 'macro') { Build-EdMacroChips }
}

function Build-EdMacroChips {
    $EdMacroChips.Children.Clear()
    if (@($MacroCfg.Macros).Count -eq 0) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = 'No macros yet - record one first.'; $tb.FontSize = 12; $tb.Foreground = Get-Brush '#7F8BA6'; $tb.Margin = [System.Windows.Thickness]::new(0, 0, 0, 6)
        [void]$EdMacroChips.Children.Add($tb)
        return
    }
    foreach ($mc in $MacroCfg.Macros) {
        $rb = New-Object System.Windows.Controls.RadioButton
        $rb.Style = $Window.FindResource('Chip'); $rb.GroupName = 'edmac'
        $rb.Content = [string]$mc.Name; $rb.Tag = $mc.Id
        $rb.Margin = [System.Windows.Thickness]::new(0, 0, 6, 6)
        if ($mc.Id -eq $Ed.MacroId) { $rb.IsChecked = $true }
        $rb.Add_Checked({ param($s, $e) $script:Ed.MacroId = [string]$s.Tag })
        [void]$EdMacroChips.Children.Add($rb)
    }
}

function Select-MacroTrigger([string]$trig) {
    Stop-KeyCapture
    $HotkeyHint.Visibility = 'Collapsed'
    $script:MacroSel = $trig
    $p = Get-MacroProfile $MacroProfileId
    $b = $p.Bind[$trig]
    $isHk = $trig -like 'KEY:*'
    $EdTitle.Text = Get-TriggerName $trig
    $EdSub.Text = $(if ($isHk) { "Keyboard hotkey  -  profile $($p.Name)" } else { "Mouse button  -  profile $($p.Name)" })
    $BtnEdClear.Content = $(if ($isHk) { 'Remove hotkey' } else { 'Reset to default' })
    $EdMsg.Text = ''
    $script:Ed = @{ Vk = [int]$b.Vk; Vks = @(@($b.Vks) | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ }); MacroId = [string]$b.MacroId; Media = $(if ($b.Media) { [string]$b.Media } else { 'playpause' }); Speed = $(if ($b.Speed) { [int]$b.Speed } else { 4 }) }
    if (-not $Ed.MacroId -and @($MacroCfg.Macros).Count -gt 0) { $script:Ed.MacroId = $MacroCfg.Macros[0].Id }
    $EdRemapKey.Content = $(if ($Ed.Vk) { "Key: $(Get-VkName $Ed.Vk)" } else { 'Click, then press a key' })
    $EdComboKey.Content = $(if ($Ed.Vks.Count) { (@($Ed.Vks | ForEach-Object { Get-VkName $_ }) -join ' + ') } else { 'Click, then press e.g. Ctrl + C' })
    $EdText.Text = [string]$b.Text
    $EdRunPath.Text = [string]$b.Path
    $EdSnVal.Text = [string]$Ed.Speed
    foreach ($c in @($MdPlay, $MdNext, $MdPrev, $MdUp, $MdDown, $MdMute)) { $c.IsChecked = ([string]$c.Tag -eq $Ed.Media) }
    $game = [bool]$p.Game
    foreach ($o in @($OptCombo, $OptText, $OptMacro, $OptRun, $OptMedia)) { $o.IsEnabled = -not $game }
    $EdGameNote.Visibility = $(if ($game) { 'Visible' } else { 'Collapsed' })
    $kind = $(if ($b) { [string]$b.Kind } else { 'remap' })
    if ($game -and $SimpleKinds -notcontains $kind) { $kind = 'remap' }
    Set-EdKind $kind
    Build-MacroMap
    Build-HotkeyList
}

function Save-MacroBinding {
    Stop-KeyCapture
    $p = Get-MacroProfile $MacroProfileId
    $kind = Get-EdKind
    $err = $null
    $b = @{ Kind = $kind }
    switch ($kind) {
        'remap' { if (-not $Ed.Vk) { $err = 'Click the box and press the key it should send.' } else { $b.Vk = [int]$Ed.Vk } }
        'combo' { if ($Ed.Vks.Count -eq 0) { $err = 'Click the box and press the key combination.' } else { $b.Vks = @($Ed.Vks) } }
        'text' { if (-not $EdText.Text) { $err = 'Type the text first.' } else { $b.Text = [string]$EdText.Text } }
        'macro' { if (-not (Get-MacroById $Ed.MacroId)) { $err = 'Choose a macro (or record one first).' } else { $b.MacroId = [string]$Ed.MacroId } }
        'run' {
            $path = ([string]$EdRunPath.Text).Trim().Trim('"')
            if ($path -match '^www\.') { $path = 'https://' + $path }
            if (-not $path) { $err = 'Enter a program, file or website.' }
            elseif ($path -notmatch '^https?://' -and -not (Test-Path -LiteralPath $path)) { $err = 'That file was not found. Use "Browse..." or a link starting with https://' }
            else { $b.Path = $path; $EdRunPath.Text = $path }
        }
        'media' { $b.Media = [string]$Ed.Media }
        'sniper' { $b.Speed = [int]$Ed.Speed }
    }
    if (-not $err -and $p.Game -and $SimpleKinds -notcontains $kind) { $err = 'Game profiles only allow 1:1 remaps, Sniper mode and Disable.' }
    if ($err) { $EdMsg.Foreground = Get-Brush '#F87171'; $EdMsg.Text = $err; return }
    $p.Bind[$MacroSel] = $b
    if ($MacroPendingHk -eq $MacroSel) { $script:MacroPendingHk = $null }
    Save-Macros
    Build-MacroMap; Build-HotkeyList
    $EdMsg.Foreground = Get-Brush '#5BE39A'
    $EdMsg.Text = "Saved: $(Get-TriggerName $MacroSel) -> $(Get-ActionText $b)"
    if (-not $MacroCfg.Enabled) { $EdMsg.Text += '  (Macros are switched off at the top right.)' }
    Write-Log "Macro saved in $($p.Name): $(Get-TriggerName $MacroSel) -> $(Get-ActionText $b)"
}

function Clear-MacroBinding {
    Stop-KeyCapture
    $p = Get-MacroProfile $MacroProfileId
    if ($p.Bind.ContainsKey($MacroSel)) { $p.Bind.Remove($MacroSel); Save-Macros }
    if ($MacroSel -like 'KEY:*') {
        $script:MacroPendingHk = $null
        Select-MacroTrigger 'MOUSE_MIDDLE'
        $EdMsg.Foreground = Get-Brush '#5BE39A'; $EdMsg.Text = 'Hotkey removed.'
    } else {
        Select-MacroTrigger $MacroSel
        $EdMsg.Foreground = Get-Brush '#5BE39A'; $EdMsg.Text = 'Back to the normal button function.'
    }
}

# ---- key capture (editor + recorder)
function Start-KeyCapture([string]$mode) {
    Stop-KeyCapture
    $script:CaptureMode = $mode
    switch ($mode) {
        'remap' { $EdRemapKey.Content = 'Press a key...  (Esc = cancel)' }
        'combo' { $EdComboKey.Content = 'Press the combination...  (Esc = cancel)' }
        'hotkey' { $BtnAddHotkey.Content = 'Press a key...'; $HotkeyHint.Visibility = 'Collapsed' }
        'stepkey' { $BtnInsKey.Content = 'Press a key...' }
    }
}

function Stop-KeyCapture {
    if (-not $CaptureMode) { return }
    $m = $CaptureMode
    $script:CaptureMode = $null
    if ($m -eq 'remap') { $EdRemapKey.Content = $(if ($Ed.Vk) { "Key: $(Get-VkName $Ed.Vk)" } else { 'Click, then press a key' }) }
    if ($m -eq 'combo') { $EdComboKey.Content = $(if ($Ed.Vks.Count) { (@($Ed.Vks | ForEach-Object { Get-VkName $_ }) -join ' + ') } else { 'Click, then press e.g. Ctrl + C' }) }
    if ($m -eq 'hotkey') { $BtnAddHotkey.Content = '+ Add hotkey' }
    if ($m -eq 'stepkey') { $BtnInsKey.Content = '+ Key' }
}

function Invoke-KeyCapture($e) {
    if (-not $CaptureMode) { return }
    $k = $e.Key
    if ($k -eq [System.Windows.Input.Key]::System) { $k = $e.SystemKey }
    if ($k -eq [System.Windows.Input.Key]::ImeProcessed) { $k = $e.ImeProcessedKey }
    $e.Handled = $true
    if ($k -eq [System.Windows.Input.Key]::Escape) { Stop-KeyCapture; return }
    $vk = [System.Windows.Input.KeyInterop]::VirtualKeyFromKey($k)
    if ($vk -le 0) { return }
    $isMod = @(0x10, 0x11, 0x12, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x5B, 0x5C) -contains $vk
    $mods = [System.Windows.Input.Keyboard]::Modifiers
    $ctrl = ($mods -band [System.Windows.Input.ModifierKeys]::Control) -ne 0
    $alt = ($mods -band [System.Windows.Input.ModifierKeys]::Alt) -ne 0
    $shift = ($mods -band [System.Windows.Input.ModifierKeys]::Shift) -ne 0
    $win = ($mods -band [System.Windows.Input.ModifierKeys]::Windows) -ne 0
    switch ($CaptureMode) {
        'remap' { $script:Ed.Vk = $vk; Stop-KeyCapture }
        'stepkey' {
            $mac = Get-MacroById $MacSelId
            Stop-KeyCapture
            if ($mac) { Add-MacStep @{ Type = 'press'; Vk = $vk } }
        }
        'combo' {
            if ($isMod) { return }   # wait for the main key
            $l = @(); if ($ctrl) { $l += 0x11 }; if ($alt) { $l += 0x12 }; if ($shift) { $l += 0x10 }; if ($win) { $l += 0x5B }
            $script:Ed.Vks = @($l + $vk)
            Stop-KeyCapture
        }
        'hotkey' {
            if ($isMod) { return }
            $trig = [SBMacro]::ComboName($vk, $ctrl, $alt, $shift, $win)
            Stop-KeyCapture
            $p = Get-MacroProfile $MacroProfileId
            if (-not $p.Bind.ContainsKey($trig)) { $script:MacroPendingHk = $trig }
            Select-MacroTrigger $trig
            $plain = (-not ($ctrl -or $alt -or $win)) -and (($vk -ge 0x30 -and $vk -le 0x5A) -or @(0x08, 0x09, 0x0D, 0x20) -contains $vk)
            if ($plain -and -not $p.Game) {
                $HotkeyHint.Text = "Careful: while this profile is active, $(Get-TriggerName $trig) will no longer type normally. F13-F24, numpad keys or Ctrl/Alt combos are safer."
                $HotkeyHint.Visibility = 'Visible'
            }
            $EdMsg.Foreground = Get-Brush '#9AA5BF'; $EdMsg.Text = 'Choose what the hotkey should do, then click Save.'
        }
    }
}

# ---- profiles
function Add-MacroProfileFromExe([string]$path, [string]$name, $isGame) {
    $exe = [IO.Path]::GetFileNameWithoutExtension($path).ToLower()
    if ($exe -eq 'powershell' -or $exe -eq 'silvanboost') { Show-Msg 'Silvan Boost itself cannot get a profile.' | Out-Null; return }
    $ex = @($MacroCfg.Profiles | Where-Object { $_.Exe -eq $exe })[0]
    if ($ex) { $script:MacroProfileId = $ex.Id; Build-ProfileList; Refresh-MacroProfileUI; Select-MacroTrigger 'MOUSE_MIDDLE'; return }
    if (-not $name) {
        try { $name = [Diagnostics.FileVersionInfo]::GetVersionInfo($path).ProductName } catch { }
        if (-not $name -or $name.Length -gt 32) { $name = [IO.Path]::GetFileNameWithoutExtension($path) }
    }
    if ($null -eq $isGame) {
        if ($Sync.Watch -and $Sync.Watch.ContainsKey($exe)) { $isGame = $true }
        else {
            $r = Show-Msg "Is '$name' a game?`n`nYes = game profile: only 1:1 key remaps, Sniper mode and Disable (safe with anti-cheat).`nNo = normal app profile with all actions." 'New profile' 'YesNoCancel' 'Question'
            if ([string]$r -eq 'Cancel') { return }
            $isGame = ([string]$r -eq 'Yes')
        }
    }
    $p = @{ Id = 'p' + [guid]::NewGuid().ToString('N').Substring(0, 8); Name = $name; Exe = $exe; Game = [bool]$isGame; Bind = @{} }
    $MacroCfg.Profiles = @($MacroCfg.Profiles) + , $p
    $script:MacroProfileId = $p.Id
    Save-Macros
    Build-ProfileList; Refresh-MacroProfileUI; Select-MacroTrigger 'MOUSE_MIDDLE'
    Write-Log "Macro profile added: $name ($exe.exe)"
}

function Show-AddProfileMenu {
    $menu = New-Object System.Windows.Controls.ContextMenu
    $menu.PlacementTarget = $BtnAddProfile
    $menu.Placement = [System.Windows.Controls.Primitives.PlacementMode]::Bottom
    $have = @($MacroCfg.Profiles | ForEach-Object { $_.Exe })
    $n = 0
    if ($GamesLoaded) {
        foreach ($g in @($Games | Where-Object { @($_.Found).Count -gt 0 })) {
            $exe = [IO.Path]::GetFileNameWithoutExtension([string]@($g.Found)[0]).ToLower()
            if ($have -contains $exe) { continue }
            $mi = New-Object System.Windows.Controls.MenuItem
            $mi.Header = "$($g.Name)  (game)"
            $mi.Tag = @{ Path = [string]@($g.Found)[0]; Name = [string]$g.Name }
            $mi.Add_Click({ param($s, $e) try { Add-MacroProfileFromExe $s.Tag.Path $s.Tag.Name $true } catch { Write-Log "Profile error: $_" } })
            [void]$menu.Items.Add($mi); $n++
        }
    }
    if ($n -gt 0) { [void]$menu.Items.Add((New-Object System.Windows.Controls.Separator)) }
    $mi = New-Object System.Windows.Controls.MenuItem
    $mi.Header = 'Choose a program (.exe)...'
    $mi.Add_Click({
            try {
                $dlg = New-Object Microsoft.Win32.OpenFileDialog
                $dlg.Title = 'Choose the program or game (.exe)'; $dlg.Filter = 'Program (*.exe)|*.exe'
                if ($dlg.ShowDialog($Window)) { Add-MacroProfileFromExe $dlg.FileName '' $null }
            } catch { Write-Log "Profile error: $_" } })
    [void]$menu.Items.Add($mi)
    $menu.IsOpen = $true
}

function Remove-MacroProfile {
    if ($MacroProfileId -eq 'desktop') { return }
    $p = Get-MacroProfile $MacroProfileId
    $r = Show-Msg "Remove the profile '$($p.Name)' and its button settings?" 'Remove profile' 'YesNo' 'Question'
    if ([string]$r -ne 'Yes') { return }
    $MacroCfg.Profiles = @($MacroCfg.Profiles | Where-Object { $_.Id -ne $p.Id })
    $script:MacroProfileId = 'desktop'
    if ($MacroActiveId -eq $p.Id) { $script:MacroActiveId = 'desktop' }
    Save-Macros
    Build-ProfileList; Refresh-MacroProfileUI; Select-MacroTrigger 'MOUSE_MIDDLE'
}

# ---- recorder
function Build-MacroList {
    $MacList.Children.Clear()
    if (@($MacroCfg.Macros).Count -eq 0) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = 'Nothing recorded yet.'; $tb.FontSize = 12; $tb.Foreground = Get-Brush '#7F8BA6'; $tb.Margin = [System.Windows.Thickness]::new(4, 0, 0, 4)
        [void]$MacList.Children.Add($tb)
        return
    }
    foreach ($mc in $MacroCfg.Macros) {
        $n = @($mc.Steps | Where-Object { $_.Type -ne 'delay' }).Count
        $x = @"
<StackPanel $NS>
  <TextBlock Text="$(X $mc.Name)" FontSize="13" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
  <TextBlock Text="$n actions" FontSize="11" Foreground="#7F8BA6"/>
</StackPanel>
"@
        $rb = New-Object System.Windows.Controls.RadioButton
        $rb.Style = $Window.FindResource('ListRow'); $rb.GroupName = 'maclist'
        $rb.Content = [System.Windows.Markup.XamlReader]::Parse($x); $rb.Tag = $mc.Id
        if ($mc.Id -eq $MacSelId) { $rb.IsChecked = $true }
        $rb.Add_Checked({ param($s, $e) try { Select-Macro ([string]$s.Tag) } catch { Write-Log "Macro UI error: $_" } })
        [void]$MacList.Children.Add($rb)
    }
}

function Select-Macro([string]$id) {
    if ([SBMacro]::Recording) { Stop-MacroRecording }
    $script:MacSelId = $id
    $mac = Get-MacroById $id
    $MacMsg.Text = ''
    if (-not $mac) {
        $MacEditor.IsEnabled = $false; $MacEditor.Opacity = 0.5
        $MacName.Text = ''; $MacSteps.Children.Clear()
        $MacInfo.Text = 'Click "+ New macro" to record your first one.'
        return
    }
    $MacEditor.IsEnabled = $true; $MacEditor.Opacity = 1
    $MacName.Text = [string]$mac.Name
    $rep = $(if ($mac.Repeat) { [string]$mac.Repeat } else { 'once' })
    $RepOnce.IsChecked = ($rep -eq 'once'); $RepHeld.IsChecked = ($rep -eq 'held'); $RepToggle.IsChecked = ($rep -eq 'toggle')
    Build-MacSteps
}

function Get-StepText($s) {
    $btn = @{ 1 = 'left mouse button'; 2 = 'right mouse button'; 3 = 'middle mouse button'; 4 = 'mouse back'; 5 = 'mouse forward' }
    switch ([string]$s.Type) {
        'down' { return "Hold $(Get-VkName ([int]$s.Vk))" }
        'up' { return "Release $(Get-VkName ([int]$s.Vk))" }
        'press' { return "Press $(Get-VkName ([int]$s.Vk))" }
        'mdown' { return "Hold $($btn[[int]$s.Button])" }
        'mup' { return "Release $($btn[[int]$s.Button])" }
        'click' { return "Click $($btn[[int]$s.Button])" }
        'text' { return 'Type' }
        'delay' { return 'Wait' }
    }
    [string]$s.Type
}

function Build-MacSteps {
    $MacSteps.Children.Clear()
    $mac = Get-MacroById $MacSelId
    if (-not $mac) { return }
    $steps = @($mac.Steps)
    $total = 0; foreach ($s in $steps) { if ($s.Type -eq 'delay') { $total += [int]$s.Ms } }
    $MacInfo.Text = $(if ($steps.Count -eq 0) { 'Empty. Click Record, then press keys or click in any window - or insert steps below.' } else { "$($steps.Count) steps  -  about $([Math]::Round($total / 1000.0, 2).ToString($Inv)) s per run" })
    $i = 0
    foreach ($s in $steps) {
        $isDelay = $s.Type -eq 'delay'
        $isText = $s.Type -eq 'text'
        $icon = '&#xE765;'
        if ($isDelay) { $icon = '&#xE916;' } elseif ($s.Type -in 'mdown', 'mup', 'click') { $icon = '&#xE962;' } elseif ($isText) { $icon = '&#xE8D2;' }
        $col = $(if ($isDelay) { '#7F8BA6' } elseif ($s.Type -in 'down', 'mdown') { '#FFA24A' } elseif ($s.Type -in 'up', 'mup') { '#5BE39A' } else { '#E8ECF5' })
        $field = ''
        if ($isDelay) { $field = "<StackPanel Orientation=`"Horizontal`" Margin=`"10,0,0,0`"><TextBox x:Name=`"Val`" Style=`"{DynamicResource Field}`" Width=`"74`" Text=`"$([int]$s.Ms)`" Padding=`"6,2`"/><TextBlock Text=`"ms`" Foreground=`"#7F8BA6`" VerticalAlignment=`"Center`" Margin=`"6,0,0,0`"/></StackPanel>" }
        if ($isText) { $field = "<TextBox x:Name=`"Val`" Style=`"{DynamicResource Field}`" Width=`"220`" Text=`"$(X ([string]$s.Text))`" Margin=`"10,0,0,0`" Padding=`"6,2`"/>" }
        $x = @"
<Border $NS CornerRadius="8" Background="$(if ($i % 2) { '#0C1424' } else { '#0E1628' })" Padding="10,5" Margin="0,0,0,3">
  <DockPanel>
    <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
      <Button x:Name="Up" Style="{DynamicResource SmallBtn}" Content="&#xE70E;" FontFamily="Segoe MDL2 Assets" Padding="7,3" Margin="4,0,0,0" ToolTip="Move up"/>
      <Button x:Name="Dn" Style="{DynamicResource SmallBtn}" Content="&#xE70D;" FontFamily="Segoe MDL2 Assets" Padding="7,3" Margin="4,0,0,0" ToolTip="Move down"/>
      <Button x:Name="Rm" Style="{DynamicResource SmallBtn}" Content="&#xE711;" FontFamily="Segoe MDL2 Assets" Padding="7,3" Margin="4,0,0,0" ToolTip="Remove"/>
    </StackPanel>
    <TextBlock Text="$($i + 1)" Width="28" FontSize="11" Foreground="#4A5675" VerticalAlignment="Center"/>
    <TextBlock Text="$icon" FontFamily="Segoe MDL2 Assets" FontSize="12" Width="22" Foreground="$col" VerticalAlignment="Center"/>
    <TextBlock Text="$(X (Get-StepText $s))" FontSize="12.5" Foreground="$col" VerticalAlignment="Center"/>
    $field
  </DockPanel>
</Border>
"@
        $row = [System.Windows.Markup.XamlReader]::Parse($x)
        foreach ($nm in 'Up', 'Dn', 'Rm') { $row.FindName($nm).Tag = $i }
        $row.FindName('Up').IsEnabled = ($i -gt 0)
        $row.FindName('Dn').IsEnabled = ($i -lt $steps.Count - 1)
        $row.FindName('Up').Add_Click({ param($sd, $e) try { Move-MacStep ([int]$sd.Tag) -1 } catch { } })
        $row.FindName('Dn').Add_Click({ param($sd, $e) try { Move-MacStep ([int]$sd.Tag) 1 } catch { } })
        $row.FindName('Rm').Add_Click({ param($sd, $e) try { Remove-MacStep ([int]$sd.Tag) } catch { } })
        $v = $row.FindName('Val')
        if ($v) {
            $v.Tag = $i
            $v.Add_LostFocus({ param($sd, $e) try { Set-MacStepValue ([int]$sd.Tag) ([string]$sd.Text) } catch { } })
            $v.Add_KeyDown({ param($sd, $e) if ($e.Key -eq 'Return') { try { Set-MacStepValue ([int]$sd.Tag) ([string]$sd.Text) } catch { } } })
        }
        [void]$MacSteps.Children.Add($row)
        $i++
    }
}

function Set-MacStepValue([int]$i, [string]$val) {
    $mac = Get-MacroById $MacSelId; if (-not $mac) { return }
    $steps = @($mac.Steps); if ($i -ge $steps.Count) { return }
    $s = $steps[$i]
    if ($s.Type -eq 'delay') {
        $n = 0; if (-not [int]::TryParse($val.Trim(), [ref]$n)) { $n = [int]$s.Ms }
        $n = [Math]::Max(0, [Math]::Min(60000, $n))
        if ($n -eq [int]$s.Ms) { return }
        $s.Ms = $n
    } elseif ($s.Type -eq 'text') {
        if ($val -eq [string]$s.Text) { return }
        $s.Text = $val
    } else { return }
    Save-Macros
    $total = 0; foreach ($x in $steps) { if ($x.Type -eq 'delay') { $total += [int]$x.Ms } }
    $MacInfo.Text = "$($steps.Count) steps  -  about $([Math]::Round($total / 1000.0, 2).ToString($Inv)) s per run"
}

function Move-MacStep([int]$i, [int]$d) {
    $mac = Get-MacroById $MacSelId; if (-not $mac) { return }
    $l = New-Object System.Collections.ArrayList; foreach ($s in @($mac.Steps)) { [void]$l.Add($s) }
    $j = $i + $d
    if ($j -lt 0 -or $j -ge $l.Count) { return }
    $t = $l[$i]; $l[$i] = $l[$j]; $l[$j] = $t
    $mac.Steps = @($l.ToArray())
    Save-Macros; Build-MacSteps
}

function Remove-MacStep([int]$i) {
    $mac = Get-MacroById $MacSelId; if (-not $mac) { return }
    $l = New-Object System.Collections.ArrayList; foreach ($s in @($mac.Steps)) { [void]$l.Add($s) }
    if ($i -lt 0 -or $i -ge $l.Count) { return }
    $l.RemoveAt($i)
    $mac.Steps = @($l.ToArray())
    Save-Macros; Build-MacSteps; Build-MacroList
}

function Add-MacStep($step) {
    $mac = Get-MacroById $MacSelId; if (-not $mac) { return }
    $old = @($mac.Steps)
    # a short gap between actions, so games and apps register every key
    if ($step.Type -ne 'delay' -and $old.Count -gt 0 -and $old[-1].Type -ne 'delay') { $old += , @{ Type = 'delay'; Ms = 30 } }
    $mac.Steps = @($old + , $step)
    Save-Macros; Build-MacSteps; Build-MacroList
}

function New-Macro {
    $n = @($MacroCfg.Macros).Count + 1
    $mac = @{ Id = 'm' + [guid]::NewGuid().ToString('N').Substring(0, 8); Name = "Macro $n"; Steps = @(); Repeat = 'once' }
    $MacroCfg.Macros = @($MacroCfg.Macros) + , $mac
    $script:MacSelId = $mac.Id
    Save-State
    Build-MacroList; Select-Macro $mac.Id
    $MacName.Focus() | Out-Null; $MacName.SelectAll()
}

function Remove-Macro {
    $mac = Get-MacroById $MacSelId; if (-not $mac) { return }
    $used = 0
    foreach ($p in $MacroCfg.Profiles) { foreach ($k in @($p.Bind.Keys)) { if ($p.Bind[$k].Kind -eq 'macro' -and $p.Bind[$k].MacroId -eq $mac.Id) { $used++ } } }
    $extra = $(if ($used) { "`n`nIt is used on $used button(s) / hotkey(s) - they go back to normal." } else { '' })
    $r = Show-Msg "Delete the macro '$($mac.Name)'?$extra" 'Delete macro' 'YesNo' 'Question'
    if ([string]$r -ne 'Yes') { return }
    foreach ($p in $MacroCfg.Profiles) { foreach ($k in @($p.Bind.Keys)) { if ($p.Bind[$k].Kind -eq 'macro' -and $p.Bind[$k].MacroId -eq $mac.Id) { $p.Bind.Remove($k) } } }
    $MacroCfg.Macros = @($MacroCfg.Macros | Where-Object { $_.Id -ne $mac.Id })
    $script:MacSelId = $(if (@($MacroCfg.Macros).Count) { $MacroCfg.Macros[0].Id } else { $null })
    Save-Macros
    Build-MacroList; Select-Macro $MacSelId
}

function Save-MacroName {
    $mac = Get-MacroById $MacSelId; if (-not $mac) { return }
    $n = ([string]$MacName.Text).Trim()
    if (-not $n) { $MacName.Text = [string]$mac.Name; return }
    if ($n.Length -gt 40) { $n = $n.Substring(0, 40) }
    if ($n -eq [string]$mac.Name) { return }
    $mac.Name = $n
    Save-State
    Build-MacroList
}

function Set-MacroRepeat([string]$rep) {
    $mac = Get-MacroById $MacSelId; if (-not $mac) { return }
    if ([string]$mac.Repeat -eq $rep) { return }
    $mac.Repeat = $rep
    Save-Macros
    $MacMsg.Foreground = Get-Brush '#5BE39A'
    $MacMsg.Text = @{ once = 'Plays once per press.'; held = 'Repeats as long as you hold the button.'; toggle = 'First press starts it, second press stops it.' }[$rep]
}

function Start-MacroRecording {
    $mac = Get-MacroById $MacSelId; if (-not $mac) { return }
    Stop-KeyCapture
    [SBMacro]::StartRecording([bool]$RecDelaysTg.IsChecked)
    [SBMacro]::Start()
    if (-not [SBMacro]::IsRunning) {
        [void][SBMacro]::StopRecording()
        $MacMsg.Foreground = Get-Brush '#F87171'; $MacMsg.Text = "Recording is not possible: $([SBMacro]::LastError)"
        Update-MacroEngine
        return
    }
    $BtnRec.Content = 'Stop'
    $MacRecBanner.Visibility = 'Visible'; Invoke-AnimateIn $MacRecBanner 4 180
    $MacRecTxt.Text = 'Recording - press keys or click in any window (keys typed here count too). Click Stop when done.'
    $pulse = New-Anim 0.25 600 0 1; $pulse.AutoReverse = $true; $pulse.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
    $MacRecDot.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $pulse)
    foreach ($b in @($BtnMacDel, $BtnMacTest, $BtnInsKey, $BtnInsDelay, $BtnInsClick, $BtnInsText, $BtnMacNew, $BtnRecBack)) { $b.IsEnabled = $false }
    $script:RecTimer = New-Object System.Windows.Threading.DispatcherTimer
    $RecTimer.Interval = [TimeSpan]::FromMilliseconds(250)
    $RecTimer.Add_Tick({ try { $MacRecTxt.Text = "Recording - $([SBMacro]::RecordedCount) steps so far. Press keys or click in any window. Click Stop when done." } catch { } })
    $RecTimer.Start()
}

function Stop-MacroRecording {
    if (-not [SBMacro]::Recording) { return }
    $steps = [SBMacro]::StopRecording()
    if ($RecTimer) { $RecTimer.Stop() }
    $MacRecDot.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $null)
    $MacRecBanner.Visibility = 'Collapsed'
    $BtnRec.Content = 'Record'
    foreach ($b in @($BtnMacDel, $BtnMacTest, $BtnInsKey, $BtnInsDelay, $BtnInsClick, $BtnInsText, $BtnMacNew, $BtnRecBack)) { $b.IsEnabled = $true }
    $mac = Get-MacroById $MacSelId
    $new = @()
    foreach ($s in @($steps)) {
        $h = @{ Type = [string]$s.Type }
        if ($s.Vk) { $h.Vk = [int]$s.Vk }
        if ($s.Button) { $h.Button = [int]$s.Button }
        if ($s.Type -eq 'delay') { $h.Ms = [int]$s.Ms }
        $new += , $h
    }
    if ($mac -and $new.Count -gt 0) {
        $old = @($mac.Steps)
        if ($old.Count -gt 0 -and $new[0].Type -ne 'delay') { $new = @(@{ Type = 'delay'; Ms = 50 }) + $new }
        $all = @($old + $new)
        if ($all.Count -gt 1000) { $all = $all[0..999]; $MacMsg.Text = 'Macro trimmed to 1000 steps.' }
        $mac.Steps = $all
        $MacMsg.Foreground = Get-Brush '#5BE39A'; $MacMsg.Text = "Recorded $($new.Count) steps. Put the macro on a button: Back to Macros > choose a button > Run a macro."
    } else {
        $MacMsg.Foreground = Get-Brush '#9AA5BF'; $MacMsg.Text = 'Nothing was recorded.'
    }
    Save-Macros
    Build-MacSteps; Build-MacroList
}

function Test-Macro {
    $mac = Get-MacroById $MacSelId
    if (-not $mac -or @($mac.Steps).Count -eq 0) { $MacMsg.Foreground = Get-Brush '#9AA5BF'; $MacMsg.Text = 'Record or insert some steps first.'; return }
    [SBMacro]::TestPlay((ConvertTo-SBSteps $mac.Steps), 3000)
    $MacMsg.Foreground = Get-Brush '#FFA24A'
    $MacMsg.Text = 'Switch to another window (e.g. Notepad) - the macro plays there in 3 seconds. It never plays inside a game or inside Silvan Boost.'
}

# ---- connected mouse + keyboard
$script:VidBrand = @{ '046D' = 'Logitech'; '1038' = 'SteelSeries'; '1532' = 'Razer'; '1B1C' = 'Corsair'; '0951' = 'HyperX'; '03F0' = 'HyperX'
    '1E7D' = 'ROCCAT'; '0B05' = 'ASUS'; '045E' = 'Microsoft'; '3434' = 'Keychron'; '31E3' = 'Wooting'; '17EF' = 'Lenovo'; '413C' = 'Dell'; '046A' = 'Cherry'
    '258A' = 'Glorious'; '22D4' = 'Glorious'; '3367' = 'Endgame Gear'; '1915' = 'Lamzu'; '373B' = 'Pulsar'; '3554' = 'VXE'; '3710' = 'Zowie'; '0C45' = 'Microdia'; '2516' = 'Cooler Master'; '0B33' = 'Contour' }
$script:BrandColor = @{ Logitech = '#00B8FC'; SteelSeries = '#FF5200'; Razer = '#44D62C'; Corsair = '#FFD600'; HyperX = '#E31837'; ROCCAT = '#3FA9F5'; ASUS = '#FF1E3C'; Wooting = '#FFB400'; Glorious = '#E8ECF5' }
$script:DevInfo = @{}

function Start-DeviceDetect {
    $DevMouseName.Text = 'Detecting...'; $DevKbdName.Text = 'Detecting...'
    $Sync.DevBusy = $true; $Sync.DevResult = $null
    $rs = [runspacefactory]::CreateRunspace(); $rs.Open()
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
            param($Sync, $VidBrand)
            $generic = '(?i)^(HID|USB)\b|compliant|konform|input device|eingabeger|composite|verbund|keyboard device|tastaturger|^standard|receiver$|^bluetooth|^microsoft (hid|usb)|^ps/2|^gaming (mouse|keyboard)$|^(mouse|keyboard|maus|tastatur)$'
            function DevProp($id, $key) { try { [string](Get-PnpDeviceProperty -InstanceId $id -KeyName $key -ErrorAction Stop).Data } catch { '' } }
            function Find-One([string]$class) {
                $best = $null; $bestScore = -999
                foreach ($d in @(Get-PnpDevice -Class $class -PresentOnly -ErrorAction SilentlyContinue)) {
                    if ($d.Status -ne 'OK') { continue }
                    $id = [string]$d.InstanceId
                    if ($id -match '^(ROOT|SWD|TERMINPUT)\\' -or $id -match 'RDP_|TERMINPUT') { continue }
                    $vid = ''; $prod = ''
                    if ($id -match 'VID_([0-9A-F]{4})&PID_([0-9A-F]{4})') { $vid = $Matches[1].ToUpper(); $prod = $Matches[2].ToUpper() }
                    elseif ($id -match 'VID&(?:0001|0002|01|02)([0-9A-F]{4})_PID&([0-9A-F]{4})') { $vid = $Matches[1].ToUpper(); $prod = $Matches[2].ToUpper() }
                    $bus = $(if ($id -match '^ACPI|^\*PNP') { 'builtin' } elseif ($id -match '00001124|00001812|BTH') { 'bluetooth' } else { 'usb' })
                    # walk up to the USB / Bluetooth device and use the product name it reports
                    $name = ''; $cur = $id
                    for ($i = 0; $i -lt 4 -and $cur -and -not $name; $i++) {
                        foreach ($key in 'DEVPKEY_Device_BusReportedDeviceDesc', 'DEVPKEY_Device_FriendlyName') {
                            $n = (DevProp $cur $key).Trim()
                            if ($n -and $n -notmatch $generic) { $name = $n; break }
                        }
                        $cur = DevProp $cur 'DEVPKEY_Device_Parent'
                        if ($cur -match '^(USB\\ROOT|PCI\\|ACPI\\|BTH\\MS_|ROOT\\)') { break }
                    }
                    $recv = $false
                    if (-not $name) {
                        $cur = $id
                        for ($i = 0; $i -lt 4 -and $cur; $i++) {
                            $n = (DevProp $cur 'DEVPKEY_Device_BusReportedDeviceDesc').Trim()
                            if ($n -match 'Receiver|Dongle|Wireless') { $recv = $true; break }
                            $cur = DevProp $cur 'DEVPKEY_Device_Parent'
                        }
                    }
                    if ($vid -eq '046D' -and $prod -match '^C5(2[0-9A-F]|3[0-9A-F]|4[0-9A-F])$') { $recv = $true }
                    $brand = [string]$VidBrand[$vid]
                    $s = 0
                    if ($brand) { $s += 50 }
                    if ($name) { $s += 30 }
                    if ($bus -eq 'builtin') { $s -= 30 }
                    if ($class -eq 'Keyboard') {
                        if ($recv) { $s -= 35 }
                        if ($name -match 'mouse|superlight|deathadder|viper|basilisk|g502|g305|g pro x|g pro wireless|aerox|rival|prime|model [od]|xlite|zowie') { $s -= 60 }
                    } else {
                        if ($name -match 'keyboard|apex|tkl|huntsman|blackwidow|k70|k65|k100|alloy|wooting|keychron') { $s -= 60 }
                    }
                    if ($s -gt $bestScore) { $bestScore = $s; $best = @{ Vid = $vid; Pid = $prod; Name = $name; Brand = $brand; Bus = $bus; Receiver = $recv } }
                }
                $best
            }
            $r = @{}
            try { $r.Mouse = Find-One 'Mouse' } catch { }
            try { $r.Kbd = Find-One 'Keyboard' } catch { }
            $Sync.DevResult = $r
            $Sync.DevBusy = $false
            $Sync.DevDone = $true
        }).AddArgument($Sync).AddArgument($VidBrand)
    $script:DevPs = $ps
    [void]$ps.BeginInvoke()
}

function Get-DevKey($d) { if ($d -and $d.Vid) { "$($d.Vid)_$($d.Pid)" } else { 'none' } }

function Format-DevName($d, [string]$kind) {
    if (-not $d) { return @{ Name = "No $kind found"; Sub = '' } }
    $key = Get-DevKey $d
    $custom = $State.misc['DevName']
    if ($custom -is [hashtable] -and $custom[$key]) { return @{ Name = [string]$custom[$key]; Sub = (Get-DevSub $d) } }
    $n = [string]$d.Name
    $n = ($n -replace '(?i)\s*\b(gaming\s+)?(mouse|keyboard)\b\s*$', '').Trim()
    if ($d.Brand -and $n -and $n -notmatch [regex]::Escape($d.Brand)) {
        $n = $(if ($d.Brand -eq 'Logitech' -and $n -match '^(G|PRO)\b|^PRO ') { "Logitech G $n" -replace 'Logitech G G', 'Logitech G' } else { "$($d.Brand) $n" })
    }
    if (-not $n) {
        if ($d.Brand -eq 'Logitech' -and $d.Receiver) { $n = "Logitech G wireless $kind" }
        elseif ($d.Brand) { $n = "$($d.Brand) $kind" }
        else { $n = $(if ($d.Bus -eq 'builtin') { "Built-in $kind" } else { "USB $kind" }) }
    }
    @{ Name = $n; Sub = (Get-DevSub $d) }
}

function Get-DevSub($d) {
    $how = $(if ($d.Receiver) { 'Wireless receiver' } elseif ($d.Bus -eq 'bluetooth') { 'Bluetooth' } elseif ($d.Bus -eq 'builtin') { 'Built-in' } else { 'USB' })
    if ($d.Vid) { "$how  -  click the name to rename" } else { $how }
}

function Get-KbdLayout([string]$name) {
    if ($name -match '(?i)\b(60|65|75)\s*%|\bmini\b|compact') { return 'compact' }
    if ($name -match '(?i)tkl|tenkeyless|80\s*%|\b87\b') { return 'tkl' }
    'full'
}

function New-MouseArt([string]$accent) {
    $x = @"
<Viewbox $NS Stretch="Uniform" Margin="8,4">
  <Canvas Width="60" Height="90">
    <Path Data="M30,2 C46,2 56,14 56,34 L56,62 C56,78 44,88 30,88 C16,88 4,78 4,62 L4,34 C4,14 14,2 30,2 Z" Fill="#16213A" Stroke="#3A4A6E" StrokeThickness="1.5"/>
    <Path Data="M30,2 L30,34 M4,34 L56,34" Stroke="#2A3858" StrokeThickness="1.2"/>
    <Rectangle Canvas.Left="27" Canvas.Top="10" Width="6" Height="14" RadiusX="3" RadiusY="3" Fill="$accent"/>
    <Rectangle Canvas.Left="1" Canvas.Top="40" Width="4" Height="9" RadiusX="2" RadiusY="2" Fill="#4A5A80"/>
    <Rectangle Canvas.Left="1" Canvas.Top="51" Width="4" Height="9" RadiusX="2" RadiusY="2" Fill="#4A5A80"/>
    <Path Data="M14,76 Q30,84 46,76" Stroke="$accent" StrokeThickness="2" Opacity="0.85"/>
  </Canvas>
</Viewbox>
"@
    [System.Windows.Markup.XamlReader]::Parse($x)
}

function New-KeyboardArt([string]$accent, [string]$layout) {
    $cols = @{ compact = 13; tkl = 15; full = 19 }[$layout]
    $w = $cols * 6 + 6
    $sb = New-Object System.Text.StringBuilder
    for ($r = 0; $r -lt 5; $r++) {
        for ($c = 0; $c -lt $cols; $c++) {
            $gap = ($layout -eq 'tkl' -and $c -ge 12) -or ($layout -eq 'full' -and $c -ge 12)
            $xx = 3 + $c * 6 + $(if ($gap) { 2 } else { 0 })
            if ($xx + 5 -gt $w - 1) { continue }
            if ($layout -ne 'compact' -and $c -ge 12 -and $c -lt 15 -and $r -in 2, 3 -and -not ($r -eq 3 -and $c -eq 13)) { continue }
            $fill = '#2A3858'
            if (($r -eq 2 -and $c -in 1, 2, 3) -or ($r -eq 1 -and $c -eq 2)) { $fill = $accent }
            if ($r -eq 4 -and $c -ge 3 -and $c -le 8) { if ($c -eq 3) { [void]$sb.Append("<Rectangle Canvas.Left=`"$xx`" Canvas.Top=`"$(3 + $r * 6)`" Width=`"35`" Height=`"5`" RadiusX=`"1`" RadiusY=`"1`" Fill=`"#2A3858`"/>") }; continue }
            [void]$sb.Append("<Rectangle Canvas.Left=`"$xx`" Canvas.Top=`"$(3 + $r * 6)`" Width=`"5`" Height=`"5`" RadiusX=`"1`" RadiusY=`"1`" Fill=`"$fill`"/>")
        }
    }
    $x = @"
<Viewbox $NS Stretch="Uniform" Margin="6,10">
  <Canvas Width="$($w + 2)" Height="35">
    <Rectangle Width="$($w + 2)" Height="35" RadiusX="4" RadiusY="4" Fill="#16213A" Stroke="#3A4A6E" StrokeThickness="1"/>
    $($sb.ToString())
  </Canvas>
</Viewbox>
"@
    [System.Windows.Markup.XamlReader]::Parse($x)
}

function Set-DevArt($border, [string]$photoKey, $fallback) {
    $photos = $State.misc['DevPhoto']
    $path = $null
    if ($photos -is [hashtable] -and $photos[$photoKey]) { $path = [string]$photos[$photoKey] }
    if ($path -and (Test-Path -LiteralPath $path)) {
        try {
            $bmp = New-Object System.Windows.Media.Imaging.BitmapImage
            $bmp.BeginInit()
            $bmp.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
            $bmp.CreateOptions = [System.Windows.Media.Imaging.BitmapCreateOptions]::IgnoreImageCache
            $bmp.DecodePixelWidth = 240
            $bmp.UriSource = New-Object System.Uri($path)
            $bmp.EndInit(); $bmp.Freeze()
            $img = New-Object System.Windows.Controls.Image
            $img.Source = $bmp; $img.Stretch = 'UniformToFill'
            $border.Child = $img
            return
        } catch { Write-Log "Device photo could not be loaded: $($_.Exception.Message)" }
    }
    $border.Child = $fallback
}

function Complete-DeviceDetect {
    $r = $Sync.DevResult
    if (-not $r) { $r = @{} }
    $script:DevInfo = $r
    $m = $r.Mouse; $k = $r.Kbd
    $mn = Format-DevName $m 'mouse'; $kn = Format-DevName $k 'keyboard'
    $DevMouseName.Text = $mn.Name; $DevMouseSub.Text = $mn.Sub; $DevMouseName.ToolTip = $mn.Name
    $DevKbdName.Text = $kn.Name; $DevKbdSub.Text = $kn.Sub; $DevKbdName.ToolTip = $kn.Name
    $ma = $(if ($m -and $BrandColor[[string]$m.Brand]) { $BrandColor[[string]$m.Brand] } else { '#FF8A1F' })
    $ka = $(if ($k -and $BrandColor[[string]$k.Brand]) { $BrandColor[[string]$k.Brand] } else { '#FF8A1F' })
    $lay = Get-KbdLayout ([string]$kn.Name)
    Set-DevArt $DevMouseArt "m_$(Get-DevKey $m)" (New-MouseArt $ma)
    Set-DevArt $DevKbdArt "k_$(Get-DevKey $k)" (New-KeyboardArt $ka $lay)
    foreach ($el in @($DevMouseArt, $DevKbdArt)) { Invoke-AnimateIn $el 4 260 }
    if ($m -or $k) { Write-Log "Detected mouse: $($mn.Name) [$($m.Vid):$($m.Pid)]; keyboard: $($kn.Name) [$($k.Vid):$($k.Pid)]" }
}

function Set-DevPhoto([string]$which) {
    $d = $(if ($which -eq 'm') { $DevInfo.Mouse } else { $DevInfo.Kbd })
    $key = "${which}_$(Get-DevKey $d)"
    $photos = $State.misc['DevPhoto']; if (-not ($photos -is [hashtable])) { $photos = @{}; $State.misc['DevPhoto'] = $photos }
    if ($photos[$key]) {
        $r = Show-Msg "Choose a new photo?`n`nYes = choose a new photo`nNo = remove the photo and show the drawing again" 'Device photo' 'YesNoCancel' 'Question'
        if ([string]$r -eq 'Cancel') { return }
        if ([string]$r -eq 'No') {
            try { Remove-Item -LiteralPath ([string]$photos[$key]) -Force -ErrorAction SilentlyContinue } catch { }
            $photos.Remove($key); Save-State; Complete-DeviceDetect; return
        }
    }
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Title = $(if ($which -eq 'm') { 'Choose a photo of your mouse' } else { 'Choose a photo of your keyboard' })
    $dlg.Filter = 'Images (*.png;*.jpg;*.jpeg;*.webp;*.bmp)|*.png;*.jpg;*.jpeg;*.webp;*.bmp'
    if (-not $dlg.ShowDialog($Window)) { return }
    $src = $dlg.FileName
    if ((Get-Item -LiteralPath $src).Length -gt 15MB) { Show-Msg 'That image is too big (max 15 MB).' | Out-Null; return }
    New-Item -ItemType Directory -Path $ArtDir -Force | Out-Null
    $dst = Join-Path $ArtDir ("dev_$key" + [IO.Path]::GetExtension($src).ToLower())
    foreach ($old in @(Get-ChildItem -LiteralPath $ArtDir -Filter "dev_$key.*" -ErrorAction SilentlyContinue)) { try { Remove-Item -LiteralPath $old.FullName -Force } catch { } }
    Copy-Item -LiteralPath $src -Destination $dst -Force
    $photos[$key] = $dst
    Save-State
    Complete-DeviceDetect
}

function Rename-Device([string]$which) {
    $d = $(if ($which -eq 'm') { $DevInfo.Mouse } else { $DevInfo.Kbd })
    if (-not $d -or -not $d.Vid) { return }
    $key = Get-DevKey $d
    $cur = $(if ($which -eq 'm') { $DevMouseName.Text } else { $DevKbdName.Text })
    Add-Type -AssemblyName Microsoft.VisualBasic
    $n = ([string][Microsoft.VisualBasic.Interaction]::InputBox("What is your $(if ($which -eq 'm') { 'mouse' } else { 'keyboard' }) called? (e.g. the model name on the box)", 'Rename device', $cur)).Trim()
    if (-not $n -or $n -eq $cur) { return }
    $names = $State.misc['DevName']; if (-not ($names -is [hashtable])) { $names = @{}; $State.misc['DevName'] = $names }
    if ($n.Length -gt 40) { $n = $n.Substring(0, 40) }
    $names[$key] = $n
    Save-State
    Complete-DeviceDetect
}

function Register-MacroEvents {
    $OptRemap.Tag = 'remap'; $OptCombo.Tag = 'combo'; $OptText.Tag = 'text'; $OptMacro.Tag = 'macro'
    $OptRun.Tag = 'run'; $OptMedia.Tag = 'media'; $OptSniper.Tag = 'sniper'; $OptDisable.Tag = 'disable'
    foreach ($o in @($OptRemap, $OptCombo, $OptText, $OptMacro, $OptRun, $OptMedia, $OptSniper, $OptDisable)) {
        $o.Add_Checked({ param($s, $e) try { Stop-KeyCapture; Show-EdField ([string]$s.Tag); $EdMsg.Text = '' } catch { } })
    }
    foreach ($c in @($MdPlay, $MdNext, $MdPrev, $MdUp, $MdDown, $MdMute)) { $c.Add_Checked({ param($s, $e) $script:Ed.Media = [string]$s.Tag }) }
    $NavMacros.Add_Checked({ Show-Page 'Macros' })
    $MacroEnabledTg.Add_Click({ $MacroCfg.Enabled = [bool]$MacroEnabledTg.IsChecked; Save-Macros; Write-Log ("Macros on: " + [bool]$MacroCfg.Enabled) })
    $MacroAutoTg.Add_Click({ $MacroCfg.Auto = [bool]$MacroAutoTg.IsChecked; Save-State; $script:MacroLastFg = ''; Update-MacroProfile })
    $BtnAddProfile.Add_Click({ try { Show-AddProfileMenu } catch { Write-Log "Profile error: $_" } })
    $BtnDelProfile.Add_Click({ try { Remove-MacroProfile } catch { Write-Log "Profile error: $_" } })
    $HsMid.Add_Click({ Select-MacroTrigger 'MOUSE_MIDDLE' }); $MapMid.Add_Click({ Select-MacroTrigger 'MOUSE_MIDDLE' })
    $HsBack.Add_Click({ Select-MacroTrigger 'MOUSE_BACK' }); $MapBack.Add_Click({ Select-MacroTrigger 'MOUSE_BACK' })
    $HsFwd.Add_Click({ Select-MacroTrigger 'MOUSE_FORWARD' }); $MapFwd.Add_Click({ Select-MacroTrigger 'MOUSE_FORWARD' })
    $BtnAddHotkey.Add_Click({ if ($CaptureMode -eq 'hotkey') { Stop-KeyCapture } else { Start-KeyCapture 'hotkey' } })
    $EdRemapKey.Add_Click({ Start-KeyCapture 'remap' })
    $EdComboKey.Add_Click({ Start-KeyCapture 'combo' })
    $BtnEdSave.Add_Click({ try { Save-MacroBinding } catch { Write-Log "Macro save error: $_"; $EdMsg.Text = "Error: $($_.Exception.Message)" } })
    $BtnEdClear.Add_Click({ try { Clear-MacroBinding } catch { Write-Log "Macro error: $_" } })
    $BtnEdMacros.Add_Click({ Show-MacroRec })
    $BtnEdBrowse.Add_Click({
            $dlg = New-Object Microsoft.Win32.OpenFileDialog
            $dlg.Title = 'Choose a program or file'; $dlg.Filter = 'Programs (*.exe;*.lnk)|*.exe;*.lnk|All files (*.*)|*.*'
            if ($dlg.ShowDialog($Window)) { $EdRunPath.Text = $dlg.FileName } })
    $BtnSnMinus.Add_Click({ $script:Ed.Speed = [Math]::Max(1, [int]$Ed.Speed - 1); $EdSnVal.Text = [string]$Ed.Speed })
    $BtnSnPlus.Add_Click({ $script:Ed.Speed = [Math]::Min(20, [int]$Ed.Speed + 1); $EdSnVal.Text = [string]$Ed.Speed })
    $BtnOpenRecorder.Add_Click({ Show-MacroRec })
    $BtnRecBack.Add_Click({ if ([SBMacro]::Recording) { Stop-MacroRecording }; Show-MacroMain; Invoke-AnimateIn $MacroMainView 8 240; Select-MacroTrigger $MacroSel })
    $BtnMacNew.Add_Click({ try { New-Macro } catch { Write-Log "Macro error: $_" } })
    $BtnMacDel.Add_Click({ try { Remove-Macro } catch { Write-Log "Macro error: $_" } })
    $BtnMacTest.Add_Click({ try { Test-Macro } catch { Write-Log "Macro test error: $_" } })
    $BtnRec.Add_Click({ try { if ([SBMacro]::Recording) { Stop-MacroRecording } else { Start-MacroRecording } } catch { Write-Log "Recorder error: $_" } })
    $MacName.Add_LostFocus({ try { Save-MacroName } catch { } })
    $MacName.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { try { Save-MacroName } catch { } } })
    $RepOnce.Add_Checked({ Set-MacroRepeat 'once' }); $RepHeld.Add_Checked({ Set-MacroRepeat 'held' }); $RepToggle.Add_Checked({ Set-MacroRepeat 'toggle' })
    $BtnInsKey.Add_Click({ if ($CaptureMode -eq 'stepkey') { Stop-KeyCapture } else { Start-KeyCapture 'stepkey' } })
    $BtnInsDelay.Add_Click({ Add-MacStep @{ Type = 'delay'; Ms = 100 } })
    $BtnInsClick.Add_Click({ Add-MacStep @{ Type = 'click'; Button = 1 } })
    $BtnInsText.Add_Click({ Add-MacStep @{ Type = 'text'; Text = 'Hello' } })
    $BtnDevMousePhoto.Add_Click({ try { Set-DevPhoto 'm' } catch { Write-Log "Photo error: $_" } })
    $BtnDevKbdPhoto.Add_Click({ try { Set-DevPhoto 'k' } catch { Write-Log "Photo error: $_" } })
    $DevMouseName.Cursor = [System.Windows.Input.Cursors]::Hand; $DevKbdName.Cursor = [System.Windows.Input.Cursors]::Hand
    $DevMouseName.Add_MouseLeftButtonUp({ try { Rename-Device 'm' } catch { } })
    $DevKbdName.Add_MouseLeftButtonUp({ try { Rename-Device 'k' } catch { } })
    $Window.Add_PreviewKeyDown({ param($s, $e) if ($CaptureMode) { try { Invoke-KeyCapture $e } catch { Write-Log "Key capture error: $_"; $script:CaptureMode = $null } } })
}

$script:LangData = @'
S	Backup & Restore	Sicherung & Wiederherstellung
S	Updates & About	Updates & Info
S	Dashboard	\u00dcbersicht
S	PC Scan	PC-Scan
S	Optimize	Optimieren
S	All Optimizations	Alle Optimierungen
S	Processes	Prozesse
S	Game Presets	Spiel-Presets
S	Pro Settings	Pro-Einstellungen
S	Live Monitor	Live-Monitor
S	Network & Input	Netzwerk & Eingabe
S	Ping Booster	Ping-Booster
S	Input Lag	Input-Lag
S	Macros	Makros
S	NEW	NEU
S	FPS Optimizer	FPS-Optimierer
S	Welcome back	Willkommen zur\u00fcck
S	Scanning your PC...	Dein PC wird gescannt...
S	optimized	optimiert
S	optimizations active	Optimierungen aktiv
S	Checking your PC...	Dein PC wird gepr\u00fcft...
S	All optimizations	Alle Optimierungen
S	Right now	Gerade jetzt
S	MEMORY	ARBEITSSPEICHER
S	Next recommended step	N\u00e4chster empfohlener Schritt
S	to check	zu pr\u00fcfen
S	 to check	 zu pr\u00fcfen
S	How?	Wie?
S	Scanning...	Scan l\u00e4uft...
S	Quick actions	Schnellaktionen
S	Restore point	Wiederherstellungspunkt
S	Clean temp	Temp leeren
S	Flush DNS	DNS leeren
S	Pick how far you want to go. Only optimizations that suit this PC are applied - and every one can be undone.	W\u00e4hle, wie weit du gehen willst. Es werden nur Optimierungen angewendet, die zu diesem PC passen - und jede l\u00e4sst sich r\u00fcckg\u00e4ngig machen.
S	Safe	Sicher
S	Zero-risk optimizations for every PC. Smoother and cleaner, nothing to think about.	Risikofreie Optimierungen f\u00fcr jeden PC. Fl\u00fcssiger und aufger\u00e4umter, ohne Nachdenken.
S	Recommended	Empfohlen
S	Lowest input lag and ping for online games: power, timers, network and input tuned for competitive play.	Niedrigster Input-Lag und Ping f\u00fcr Online-Spiele: Energie, Timer, Netzwerk und Eingabe f\u00fcr kompetitives Spielen eingestellt.
S	Everything that improves performance, including small trade-offs. Advanced tweaks always stay manual.	Alles, was die Leistung verbessert, auch mit kleinen Kompromissen. Fortgeschrittene Tweaks bleiben immer manuell.
S	Apply	Anwenden
S	Show what will change	Zeigen, was sich \u00e4ndert
S	Hide details	Details ausblenden
S	Most effective single optimizations	Die wirksamsten einzelnen Optimierungen
S	Macro recorder	Makro-Recorder
S	Macros on	Makros an
S	Give your mouse buttons and hotkeys new jobs - per app, switching automatically. Works while Silvan Boost is open (minimized is fine).	Gib deinen Maustasten und Hotkeys neue Aufgaben - pro App, mit automatischem Wechsel. Funktioniert, solange Silvan Boost offen ist (minimiert reicht).
S	PROFILES	PROFILE
S	+ Add profile	+ Profil hinzuf\u00fcgen
S	Remove	Entfernen
S	Switch profiles automatically	Profile automatisch wechseln
S	MOUSE	MAUS
S	Detecting...	Wird erkannt...
S	Photo	Foto
S	KEYBOARD	TASTATUR
S	Mouse buttons	Maustasten
S	Middle button	Mittlere Taste
S	DPI button - set in your mouse's own software	DPI-Taste - in der Software deiner Maus einstellen
S	Forward (side)	Vor (Seite)
S	Back (side)	Zur\u00fcck (Seite)
S	Default	Standard
S	Left and right click stay as they are, so you can never lock yourself out. DPI and lighting are stored on the mouse - change them in your mouse's own software.	Links- und Rechtsklick bleiben wie sie sind, damit du dich nie aussperrst. DPI und Beleuchtung sind in der Maus gespeichert - \u00e4ndere sie in der Software deiner Maus.
S	+ Add hotkey	+ Hotkey hinzuf\u00fcgen
S	Keyboard hotkeys	Tastatur-Hotkeys
S	Game profile: only 1:1 key remaps, Sniper mode and Disable are allowed. Anti-cheat can ban automated input like macros, text or key combos.	Spiel-Profil: Nur 1:1-Tastenbelegung, Sniper-Modus und Deaktivieren sind erlaubt. Anti-Cheat kann automatische Eingaben wie Makros, Text oder Tastenkombis bannen.
S	Remap to a key	Auf eine Taste legen
S	Key combination	Tastenkombination
S	Type text	Text tippen
S	Run a macro	Makro abspielen
S	Open app or website	App oder Webseite \u00f6ffnen
S	Media and volume	Medien und Lautst\u00e4rke
S	Sniper mode (hold = slower pointer)	Sniper-Modus (halten = langsamerer Zeiger)
S	Disable this button	Diese Taste deaktivieren
S	Key to send	Zu sendende Taste
S	Click, then press a key	Klicken, dann eine Taste dr\u00fccken
S	Click, then press e.g. Ctrl + C	Klicken, dann z.B. Strg + C dr\u00fccken
S	Text to type	Zu tippender Text
S	Macro	Makro
S	Open macro recorder	Makro-Recorder \u00f6ffnen
S	Program, file or website	Programm, Datei oder Webseite
S	Browse...	Durchsuchen...
S	Media action	Medien-Aktion
S	Next	Weiter
S	Previous	Zur\u00fcck
S	Volume +	Lautst\u00e4rke +
S	Volume -	Lautst\u00e4rke -
S	Mute	Stumm
S	Pointer speed while held	Zeigertempo beim Halten
S	Windows scale 1 - 20 (normal is 10). Your normal speed comes back when you let go.	Windows-Skala 1 - 20 (normal ist 10). Dein normales Tempo kommt zur\u00fcck, sobald du losl\u00e4sst.
S	The button does nothing while this profile is active.	Die Taste macht nichts, solange dieses Profil aktiv ist.
S	Save	Speichern
S	Reset to default	Auf Standard zur\u00fccksetzen
S	Remove hotkey	Hotkey entfernen
S	Back to Macros	Zur\u00fcck zu Makros
S	Record keys and clicks once, then put the macro on any button or hotkey. Changes save automatically.	Nimm Tasten und Klicks einmal auf und lege das Makro dann auf eine beliebige Taste oder einen Hotkey. \u00c4nderungen werden automatisch gespeichert.
S	SAVED MACROS	GESPEICHERTE MAKROS
S	+ New macro	+ Neues Makro
S	Delete	L\u00f6schen
S	Test	Testen
S	Record	Aufnehmen
S	Repeat:	Wiederholen:
S	Once	Einmal
S	While held	Solange gedr\u00fcckt
S	Toggle on / off	An / aus schalten
S	Record real delays	Echte Pausen aufnehmen
S	Insert:	Einf\u00fcgen:
S	+ Key	+ Taste
S	+ Delay	+ Pause
S	+ Left click	+ Linksklick
S	No hotkeys yet. Click "+ Add hotkey" and press a key or combination, e.g. F13 or Ctrl + Alt + M.	Noch keine Hotkeys. Klicke "+ Hotkey hinzuf\u00fcgen" und dr\u00fccke eine Taste oder Kombination, z.B. F13 oder Strg + Alt + M.
S	No macros yet - record one first.	Noch keine Makros - nimm zuerst eins auf.
S	Hotkey removed.	Hotkey entfernt.
S	Back to the normal button function.	Zur\u00fcck zur normalen Tastenfunktion.
S	Press a key...  (Esc = cancel)	Dr\u00fccke eine Taste...  (Esc = abbrechen)
S	Press the combination...  (Esc = cancel)	Dr\u00fccke die Kombination...  (Esc = abbrechen)
S	Press a key...	Dr\u00fccke eine Taste...
S	Choose what the hotkey should do, then click Save.	W\u00e4hle, was der Hotkey tun soll, und klicke dann auf Speichern.
S	Choose a program (.exe)...	Programm ausw\u00e4hlen (.exe)...
S	Nothing recorded yet.	Noch nichts aufgenommen.
S	Click "+ New macro" to record your first one.	Klicke "+ Neues Makro", um dein erstes aufzunehmen.
S	Stop	Stopp
S	Recording - press keys or click in any window (keys typed here count too). Click Stop when done.	Aufnahme l\u00e4uft - dr\u00fccke Tasten oder klicke in einem beliebigen Fenster (Tasten hier z\u00e4hlen auch). Klicke auf Stopp, wenn du fertig bist.
S	Macro trimmed to 1000 steps.	Makro auf 1000 Schritte gek\u00fcrzt.
S	Nothing was recorded.	Es wurde nichts aufgenommen.
S	Record or insert some steps first.	Nimm zuerst Schritte auf oder f\u00fcge welche ein.
S	Switch to another window (e.g. Notepad) - the macro plays there in 3 seconds. It never plays inside a game or inside Silvan Boost.	Wechsle in ein anderes Fenster (z.B. Editor) - das Makro spielt dort in 3 Sekunden ab. In Spielen und in Silvan Boost spielt es nie.
S	Silvan Boost itself cannot get a profile.	Silvan Boost selbst kann kein Profil bekommen.
S	That image is too big (max 15 MB).	Das Bild ist zu gro\u00df (max. 15 MB).
S	Active right now	Gerade aktiv
S	Move up	Nach oben
S	Move down	Nach unten
S	Game	Spiel
S	Everywhere else	\u00dcberall sonst
S	Macros are switched off.	Makros sind ausgeschaltet.
S	Plays once per press.	Spielt einmal pro Druck.
S	Repeats as long as you hold the button.	Wiederholt, solange du die Taste h\u00e4ltst.
S	First press starts it, second press stops it.	Erster Druck startet, zweiter Druck stoppt.
S	Disabled	Deaktiviert
S	Wireless receiver	Funk-Empf\u00e4nger
S	Built-in	Eingebaut
S	Rescan	Neu scannen
S	PC Scanner	PC-Scanner
S	Your detected hardware and a gaming health check.	Deine erkannte Hardware und ein Gaming-Gesundheitscheck.
S	Gaming health check	Gaming-Gesundheitscheck
S	Revert all	Alles zur\u00fccksetzen
S	Apply recommended	Empfohlene anwenden
S	Max performance	Maximale Leistung
S	Optimizations	Optimierungen
S	Search optimizations...	Optimierungen suchen...
S	Search apps or publishers...	Apps oder Hersteller suchen...
S	Moderate	Mittel
S	Advanced	Fortgeschritten
S	Permanent	Dauerhaft
S	Action	Aktion
S	Done	Erledigt
S	Ready	Bereit
S	Active	Aktiv
S	Inactive	Inaktiv
S	Careful	Vorsicht
S	Why:	Warum:
S	Fix:	L\u00f6sung:
S	Run	Ausf\u00fchren
S	Search again	Erneut suchen
S	Add your own game	Eigenes Spiel hinzuf\u00fcgen
S	Optimized	Optimiert
S	Installed	Installiert
S	Not installed	Nicht installiert
S	Installed - Windows tweaks only	Installiert - nur Windows-Tweaks
S	Not found on this PC - Windows tweaks still apply	Nicht auf diesem PC gefunden - Windows-Tweaks gelten trotzdem
S	Pro settings	Pro-Einstellungen
S	Undo	R\u00fcckg\u00e4ngig
S	Searching for installed games (Steam, Epic, Riot, Battle.net, Roblox ...)	Suche nach installierten Spielen (Steam, Epic, Riot, Battle.net, Roblox ...)
S	The in-game settings top players use for maximum FPS and visibility - pick a game.	Die Ingame-Einstellungen der Top-Spieler f\u00fcr maximale FPS und Sicht - w\u00e4hle ein Spiel.
S	Current pro configs	Aktuelle Pro-Configs
S	Optimize Windows for this game	Windows f\u00fcr dieses Spiel optimieren
S	Compiled from public pro-settings guides (2025-2026). Every pro is a little different - use these as a strong starting point and adjust to taste.	Zusammengestellt aus \u00f6ffentlichen Pro-Settings-Guides (2025-2026). Jeder Profi ist etwas anders - nimm das als guten Startpunkt und passe es an.
S	Best performance settings	Beste Performance-Einstellungen
S	Auto-detect games	Spiele automatisch erkennen
S	IDLE	BEREIT
S	Waiting for a game... Start any game from Game Presets and it is detected automatically.	Warte auf ein Spiel... Starte ein Spiel aus den Spiel-Presets, es wird automatisch erkannt.
S	frames per second	Bilder pro Sekunde
S	slowest 1% of frames	langsamste 1% der Bilder
S	time per frame	Zeit pro Bild
S	STUTTERS	RUCKLER
S	big frame spikes	gro\u00dfe Frame-Spitzen
S	FRAMETIME GRAPH  -  flat and low = smooth, spikes = stutter	FRAMETIME-GRAPH  -  flach und niedrig = fl\u00fcssig, Spitzen = Ruckler
S	Problems detected	Erkannte Probleme
S	No problems so far. Problems appear here live while you play - with the cause and how to fix it.	Bisher keine Probleme. Probleme erscheinen hier live beim Spielen - mit Ursache und L\u00f6sung.
S	LAST SESSION REPORT	LETZTER SESSION-BERICHT
S	BACKGROUND LOAD	HINTERGRUNDLAST
S	Shown while a game is running.	Wird angezeigt, w\u00e4hrend ein Spiel l\u00e4uft.
S	HOW IT WORKS	SO FUNKTIONIERT ES
S	Keep Silvan Boost open (minimized is fine) and start a game. It is detected automatically and measured live: FPS and frame times (via Intel PresentMon), CPU, GPU, temperatures, memory, drive and ping. When the game closes, Silvan Boost pops up with a session report. Nothing is injected into the game, so it is safe with anti-cheat.	Lass Silvan Boost offen (minimiert reicht) und starte ein Spiel. Es wird automatisch erkannt und live gemessen: FPS und Frametimes (\u00fcber Intel PresentMon), CPU, GPU, Temperaturen, Speicher, Laufwerk und Ping. Wenn das Spiel schlie\u00dft, zeigt Silvan Boost einen Session-Bericht. Es wird nichts ins Spiel injiziert - sicher mit Anti-Cheat.
S	FPS counter not available	FPS-Z\u00e4hler nicht verf\u00fcgbar
S	waiting for frames...	warte auf Bilder...
S	RAM in use	RAM belegt
S	measuring...	wird gemessen...
S	Measuring...	Wird gemessen...
S	Live GPU stats need an NVIDIA driver	Live-GPU-Werte brauchen einen NVIDIA-Treiber
S	Run full test	Kompletten Test starten
S	Boost ping	Ping boosten
S	Live connection quality, game server test, bufferbloat test, DNS benchmark and every network optimization in one place.	Live-Verbindungsqualit\u00e4t, Spielserver-Test, Bufferbloat-Test, DNS-Benchmark und alle Netzwerk-Optimierungen an einem Ort.
S	to 1.1.1.1	zu 1.1.1.1
S	ping variation	Ping-Schwankung
S	PACKET LOSS	PAKETVERLUST
S	last 60 seconds	letzte 60 Sekunden
S	your home network	dein Heimnetz
S	CONNECTION	VERBINDUNG
S	LIVE PING - LAST 60 SECONDS	LIVE-PING - LETZTE 60 SEKUNDEN
S	internet	Internet
S	your router	dein Router
S	What to do	Was zu tun ist
S	Network optimizations	Netzwerk-Optimierungen
S	BUFFERBLOAT (PING UNDER LOAD)	BUFFERBLOAT (PING UNTER LAST)
S	Run the full test	Kompletten Test starten
S	Bufferbloat = how much your ping rises while the connection is busy. It is the #1 cause of lag spikes at home.	Bufferbloat = wie stark dein Ping steigt, wenn die Leitung ausgelastet ist. Das ist Ursache Nr. 1 f\u00fcr Lag-Spitzen zu Hause.
S	Bufferbloat = how much your ping rises while the connection is busy (someone streaming or downloading). It is the #1 cause of lag spikes at home.	Bufferbloat = wie stark dein Ping steigt, wenn die Leitung ausgelastet ist (jemand streamt oder l\u00e4dt herunter). Das ist Ursache Nr. 1 f\u00fcr Lag-Spitzen zu Hause.
S	GAME SERVER REGIONS	SPIELSERVER-REGIONEN
S	Ping to the data centers many online games use.	Ping zu den Rechenzentren vieler Online-Spiele.
S	Run the full test to measure.	Starte den kompletten Test zum Messen.
S	Reset to automatic	Auf automatisch zur\u00fccksetzen
S	DNS BENCHMARK	DNS-BENCHMARK
S	Run the full test to compare DNS servers.	Starte den kompletten Test, um DNS-Server zu vergleichen.
S	Ping tools	Ping-Werkzeuge
S	Trace route	Route verfolgen
S	Find the lag (route analysis)	Lag finden (Routenanalyse)
S	Measures every station between your PC and the internet and shows WHERE the delay or packet loss starts: your home network, your provider or the internet.	Misst jede Station zwischen deinem PC und dem Internet und zeigt, WO Verz\u00f6gerung oder Paketverlust beginnt: dein Heimnetz, dein Anbieter oder das Internet.
S	Test servers	Server testen
S	CS2 / Valve server ping	CS2- / Valve-Server-Ping
S	Pings every Valve data center (CS2, Deadlock, Dota 2) and shows the closest ones.	Pingt jedes Valve-Rechenzentrum (CS2, Deadlock, Dota 2) und zeigt die n\u00e4chsten.
S	Reset	Zur\u00fccksetzen
S	Run test	Test starten
S	MTU test	MTU-Test
S	Finds the biggest packet your connection can carry. DSL and some fiber lines need a smaller MTU to avoid split packets.	Findet das gr\u00f6\u00dfte Paket, das deine Leitung \u00fcbertragen kann. DSL und manche Glasfaserleitungen brauchen eine kleinere MTU, damit Pakete nicht geteilt werden.
S	Scan now	Jetzt scannen
S	Apps using your internet	Apps, die dein Internet nutzen
S	Shows which programs are connected to the internet right now and how busy they are - close the ones that eat your bandwidth.	Zeigt, welche Programme gerade mit dem Internet verbunden sind und wie stark - schlie\u00dfe die, die deine Bandbreite fressen.
S	Game Network Mode	Spiel-Netzwerkmodus
S	When the Live Monitor detects a game, Windows Update downloads (BITS, Delivery Optimization) and OneDrive are paused - and resumed when you close the game.	Wenn der Live-Monitor ein Spiel erkennt, werden Windows-Update-Downloads (BITS, \u00dcbermittlungsoptimierung) und OneDrive pausiert - und nach dem Spiel fortgesetzt.
S	Pause background downloads while a game runs	Hintergrund-Downloads pausieren, w\u00e4hrend ein Spiel l\u00e4uft
S	Scan Wi-Fi	WLAN scannen
S	Wi-Fi channel check	WLAN-Kanal-Check
S	Scans nearby Wi-Fi networks and tells you which channel is the least crowded for your router.	Scannt WLANs in der N\u00e4he und sagt dir, welcher Kanal f\u00fcr deinen Router am wenigsten belegt ist.
S	Full reset	Komplett zur\u00fccksetzen
S	Quick fix	Schnelle Reparatur
S	Network repair	Netzwerk-Reparatur
S	Fix a broken or slow connection. Quick fix is harmless; full reset restores Windows network defaults (restart needed).	Repariert eine kaputte oder langsame Verbindung. Schnelle Reparatur ist harmlos; Komplett zur\u00fccksetzen stellt die Windows-Netzwerkstandards wieder her (Neustart n\u00f6tig).
S	no internet route	keine Internetverbindung
S	Wi-Fi	WLAN
S	Ethernet	LAN
S	lost	verloren
S	router does not answer ping	Router antwortet nicht auf Ping
S	Ping under load: lost	Ping unter Last: verloren
S	The load test could not reach speed.cloudflare.com - result not reliable.	Der Lasttest konnte speed.cloudflare.com nicht erreichen - Ergebnis nicht zuverl\u00e4ssig.
S	No app is connected to the internet right now.	Gerade ist keine App mit dem Internet verbunden.
S	Sorted by current activity (network + disk). Red = heavy traffic right now - close or pause it while you play.	Sortiert nach aktueller Aktivit\u00e4t (Netzwerk + Festplatte). Rot = gerade viel Verkehr - beim Spielen schlie\u00dfen oder pausieren.
S	Windows returned no nearby networks. On Windows 11 the Wi-Fi scan needs Location access: Settings > Privacy & security > Location > on (and allow desktop apps). If you turned off location with Silvan Boost, turn it on for the scan.	Windows hat keine WLANs in der N\u00e4he gefunden. Unter Windows 11 braucht der WLAN-Scan den Standortzugriff: Einstellungen > Datenschutz & Sicherheit > Standort > ein (und Desktop-Apps erlauben). Falls du den Standort mit Silvan Boost ausgeschaltet hast, schalte ihn f\u00fcr den Scan ein.
S	The test could not run (ping is blocked on this connection).	Der Test konnte nicht laufen (Ping ist auf dieser Verbindung blockiert).
S	Network stack reset - restart your PC to finish.	Netzwerk zur\u00fcckgesetzt - starte deinen PC neu, um abzuschlie\u00dfen.
S	Adapter MTU restored to its previous value.	Adapter-MTU auf den vorherigen Wert zur\u00fcckgesetzt.
S	Checking your connection...	Deine Verbindung wird gepr\u00fcft...
S	Measuring ping to your router and the internet...	Ping zu Router und Internet wird gemessen...
S	Ping test finished.	Ping-Test fertig.
S	Flushing DNS cache...	DNS-Cache wird geleert...
S	Ping boost applied	Ping-Boost angewendet
S	Downloading the Valve server list...	Valve-Serverliste wird geladen...
S	Looking for apps that use your internet...	Suche nach Apps, die dein Internet nutzen...
S	Testing the largest packet size your connection allows...	Gr\u00f6\u00dfte m\u00f6gliche Paketgr\u00f6\u00dfe wird getestet...
S	Repairing the connection...	Verbindung wird repariert...
S	Resetting the network stack...	Netzwerk wird zur\u00fcckgesetzt...
S	DNS reset to your previous / automatic setting	DNS auf vorherige / automatische Einstellung zur\u00fcckgesetzt
S	No internet connection found.	Keine Internetverbindung gefunden.
S	Use	Nutzen
S	Max input response	Maximale Eingabe-Reaktion
S	Get every click and mouse movement onto the screen as fast as possible.	Bringt jeden Klick und jede Mausbewegung so schnell wie m\u00f6glich auf den Bildschirm.
S	MOUSE POLLING RATE	MAUS-POLLINGRATE
S	not tested yet	noch nicht getestet
S	REFRESH RATE	BILDWIEDERHOLRATE
S	INPUT OPTIMIZATIONS	INPUT-OPTIMIERUNGEN
S	PC LATENCY	PC-LATENZ
S	start a game to measure	starte ein Spiel zum Messen
S	MOUSE POLLING RATE TEST	MAUS-POLLINGRATE-TEST
S	Start test	Test starten
S	Click Start, then move your mouse fast in circles for 5 seconds.	Klicke auf Start und bewege die Maus dann 5 Sekunden lang schnell im Kreis.
S	Checklist	Checkliste
S	Input optimizations	Input-Optimierungen
S	Driver & game settings	Treiber- & Spiel-Einstellungen
S	WHAT THE NUMBERS MEAN	WAS DIE ZAHLEN BEDEUTEN
S	PC latency is the time from your click or mouse movement reaching the PC until the new image is shown - measured live in-game with Intel PresentMon. Under 25 ms is excellent. Your mouse and monitor add a few ms on top. Polling rate is how often your mouse reports its position: 1000 Hz = every 1 ms.	PC-Latenz ist die Zeit, bis dein Klick oder deine Mausbewegung als neues Bild erscheint - live im Spiel gemessen mit Intel PresentMon. Unter 25 ms ist hervorragend. Maus und Monitor kommen noch ein paar ms dazu. Die Pollingrate ist, wie oft deine Maus ihre Position meldet: 1000 Hz = jede 1 ms.
S	Move your mouse fast in circles now...	Bewege deine Maus jetzt schnell im Kreis...
S	No movement detected - click Start and keep moving the mouse for the whole 5 seconds.	Keine Bewegung erkannt - klicke auf Start und bewege die Maus die ganzen 5 Sekunden.
S	measured	gemessen
S	last measured in a game	zuletzt in einem Spiel gemessen
S	Max input response applied	Maximale Eingabe-Reaktion angewendet
S	Refresh	Aktualisieren
S	Reduce processes	Prozesse reduzieren
S	Process Reducer	Prozess-Reduzierer
S	PROCESSES	PROZESSE
S	running right now	laufen gerade
S	SERVICES RUNNING	LAUFENDE DIENSTE
S	Windows services	Windows-Dienste
S	SVCHOST PROCESSES	SVCHOST-PROZESSE
S	service host processes	Diensthost-Prozesse
S	across all processes	\u00fcber alle Prozesse
S	Reduce processes = turns off unneeded services and background features, groups Windows services and closes the apps switched on below. Windows itself always needs around 100+ processes - those are protected and never touched.	Prozesse reduzieren = schaltet unn\u00f6tige Dienste und Hintergrundfunktionen aus, gruppiert Windows-Dienste und schlie\u00dft die unten eingeschalteten Apps. Windows selbst braucht immer etwa 100+ Prozesse - die sind gesch\u00fctzt und werden nie angefasst.
S	Close selected (0)	Ausgew\u00e4hlte schlie\u00dfen (0)
S	Running apps you can close	Laufende Apps, die du schlie\u00dfen kannst
S	Windows, drivers, anti-cheat and the game you are playing are hidden and protected.	Windows, Treiber, Anti-Cheat und dein laufendes Spiel sind ausgeblendet und gesch\u00fctzt.
S	Startup apps	Autostart-Apps
S	can be grouped - see Reduce	kann gruppiert werden - siehe Reduzieren
S	grouped after next restart	nach dem n\u00e4chsten Neustart gruppiert
S	No startup apps found.	Keine Autostart-Apps gefunden.
S	See what is running and push the number of processes down as far as is safe.	Sieh, was l\u00e4uft, und dr\u00fcck die Zahl der Prozesse so weit runter, wie es sicher ist.
S	Startup app changed - takes effect at next sign-in.	Autostart-App ge\u00e4ndert - wirkt ab der n\u00e4chsten Anmeldung.
S	Counting processes...	Prozesse werden gez\u00e4hlt...
S	Closing background apps...	Hintergrund-Apps werden geschlossen...
S	Select none	Keine ausw\u00e4hlen
S	Select recommended	Empfohlene ausw\u00e4hlen
S	Remove selected (0)	Ausgew\u00e4hlte entfernen (0)
S	Bloatware cleaner	Bloatware-Entferner
S	All installed apps	Alle installierten Apps
S	Recommended downloads	Empfohlene Downloads
S	Only preinstalled apps that are on this PC are shown. Switch on every app you want to remove - removed apps can be reinstalled from the Microsoft Store.	Es werden nur vorinstallierte Apps angezeigt, die auf diesem PC sind. Schalte jede App ein, die du entfernen willst - entfernte Apps kannst du im Microsoft Store wieder installieren.
S	All	Alle
S	Programs	Programme
S	Store apps	Store-Apps
S	Sort: name	Sortieren: Name
S	Sort: size	Sortieren: Gr\u00f6\u00dfe
S	Sort: newest	Sortieren: Neueste
S	No unnecessary apps found - this PC is already clean.	Keine unn\u00f6tigen Apps gefunden - dieser PC ist schon sauber.
S	Installing...	Wird installiert...
S	Reinstall	Neu installieren
S	Install failed - use Website	Installation fehlgeschlagen - nutze Webseite
S	Install downloads the official version through winget, the Windows package manager, and installs it silently. Website opens the official download page.	Installieren l\u00e4dt die offizielle Version \u00fcber winget (den Windows-Paketmanager) und installiert sie still. Webseite \u00f6ffnet die offizielle Download-Seite.
S	winget (Windows package manager) was not found on this PC - use Website to download, or install "App Installer" from the Microsoft Store to enable one-click installs.	winget (Windows-Paketmanager) wurde auf diesem PC nicht gefunden - nutze Webseite zum Herunterladen oder installiere "App-Installer" aus dem Microsoft Store f\u00fcr Ein-Klick-Installationen.
S	Every program and Store app on this PC - search, sort and uninstall.	Jedes Programm und jede Store-App auf diesem PC - suchen, sortieren und deinstallieren.
S	Free tools that help with performance, monitoring and drivers - one click to install.	Kostenlose Tools f\u00fcr Leistung, \u00dcberwachung und Treiber - mit einem Klick installiert.
S	in use	in Benutzung
S	Program	Programm
S	Store app	Store-App
S	Keep - needed by games/drivers	Behalten - von Spielen/Treibern gebraucht
S	Uninstall	Deinstallieren
S	Website	Webseite
S	Install	Installieren
S	Close	Schlie\u00dfen
S	Looking for removable apps...	Suche nach entfernbaren Apps...
S	Reading installed apps...	Installierte Apps werden gelesen...
S	Checking installed apps...	Installierte Apps werden gepr\u00fcft...
S	Every change Silvan Boost makes is recorded, so you can always go back.	Jede \u00c4nderung von Silvan Boost wird gespeichert, damit du immer zur\u00fcck kannst.
S	Create restore point	Wiederherstellungspunkt erstellen
S	Open System Restore	Systemwiederherstellung \u00f6ffnen
S	System Restore point	Systemwiederherstellungspunkt
S	Revert all optimizations	Alle Optimierungen zur\u00fccksetzen
S	Undo everything	Alles r\u00fcckg\u00e4ngig machen
S	Puts every active optimization back to the exact value your PC had before. Removed apps can be reinstalled from the Microsoft Store.	Setzt jede aktive Optimierung genau auf den Wert zur\u00fcck, den dein PC vorher hatte. Entfernte Apps kannst du im Microsoft Store wieder installieren.
S	Open backup folder	Sicherungsordner \u00f6ffnen
S	Silvan Boost backup	Silvan-Boost-Sicherung
S	Activity log	Aktivit\u00e4tsprotokoll
S	No restore point created yet. One is created automatically before the first change of every session.	Noch kein Wiederherstellungspunkt erstellt. Vor der ersten \u00c4nderung jeder Sitzung wird automatisch einer erstellt.
S	active (advanced not counted)	aktiv (fortgeschrittene nicht gez\u00e4hlt)
S	About Silvan Boost	\u00dcber Silvan Boost
S	Check for updates	Nach Updates suchen
S	Install updates automatically	Updates automatisch installieren
S	Silvan Boost checks for a new version at every start. When off, it asks first.	Silvan Boost sucht bei jedem Start nach einer neuen Version. Wenn aus, fragt es vorher.
S	Adapted to this PC	An diesen PC angepasst
S	Silvan Boost scans the hardware every time it starts and adapts the optimizations: tweaks that cannot work on this PC are disabled, and tweaks that are a bad idea here are marked and skipped by the presets.	Silvan Boost scannt bei jedem Start die Hardware und passt die Optimierungen an: Tweaks, die auf diesem PC nicht funktionieren, sind deaktiviert, und Tweaks, die hier keine gute Idee sind, werden markiert und von den Presets \u00fcbersprungen.
S	What to expect	Was du erwarten kannst
S	Windows tweaks mostly improve consistency: fewer stutters, steadier 1% lows, snappier input. The biggest raw FPS gains on a PC like yours come from the PC Scanner checks: XMP/EXPO enabled for your RAM, Resizable BAR on, the monitor at its highest refresh rate, an up-to-date BIOS and NVIDIA driver, and NVIDIA Reflex in-game.	Windows-Tweaks verbessern vor allem die Gleichm\u00e4\u00dfigkeit: weniger Ruckler, stabilere 1% Lows, direktere Eingabe. Die gr\u00f6\u00dften FPS-Gewinne auf einem PC wie deinem kommen aus den PC-Scanner-Checks: XMP/EXPO f\u00fcr den RAM an, Resizable BAR an, der Monitor auf h\u00f6chster Bildwiederholrate, aktuelles BIOS und NVIDIA-Treiber und NVIDIA Reflex im Spiel.
S	Safety	Sicherheit
S	A System Restore point is created before the first change of each session, and every original value is saved to C:\\ProgramData\\SilvanBoost\\backup.json. Silvan Boost deliberately does not disable Microsoft Defender, Windows Update or CPU security mitigations - they cost almost no FPS and protect your PC. Advanced tweaks ask for confirmation first.	Vor der ersten \u00c4nderung jeder Sitzung wird ein Systemwiederherstellungspunkt erstellt, und jeder Originalwert wird in C:\\ProgramData\\SilvanBoost\\backup.json gespeichert. Silvan Boost schaltet Microsoft Defender, Windows Update und CPU-Sicherheitsfunktionen absichtlich nicht ab - sie kosten fast keine FPS und sch\u00fctzen deinen PC. Fortgeschrittene Tweaks fragen vorher nach.
S	Update available	Update verf\u00fcgbar
S	Restart needed to finish some optimizations	Neustart n\u00f6tig, um einige Optimierungen abzuschlie\u00dfen
S	Restart now	Jetzt neu starten
S	Starting...	Startet...
S	Automatic updates are not set up in this build.	Automatische Updates sind in dieser Version nicht eingerichtet.
S	Checking for updates...	Suche nach Updates...
S	Update information is invalid.	Update-Informationen sind ung\u00fcltig.
S	Update failed - see the activity log.	Update fehlgeschlagen - siehe Aktivit\u00e4tsprotokoll.
S	Restart	Neu starten
S	Creating a System Restore point - this can take up to a minute...	Systemwiederherstellungspunkt wird erstellt - das kann bis zu einer Minute dauern...
S	Creating a System Restore point before the first change...	Vor der ersten \u00c4nderung wird ein Systemwiederherstellungspunkt erstellt...
S	Creating a System Restore point...	Systemwiederherstellungspunkt wird erstellt...
S	System Restore point created.	Systemwiederherstellungspunkt erstellt.
S	Restore point failed.	Wiederherstellungspunkt fehlgeschlagen.
S	Scanning your hardware...	Deine Hardware wird gescannt...
S	Scan complete.	Scan abgeschlossen.
S	Checking your current Windows settings...	Deine aktuellen Windows-Einstellungen werden gepr\u00fcft...
S	Building optimizations...	Optimierungen werden vorbereitet...
S	Ready - your PC has been scanned.	Bereit - dein PC wurde gescannt.
S	All optimizations reverted.	Alle Optimierungen zur\u00fcckgesetzt.
S	Everything in this preset is already active.	Alles aus diesem Preset ist schon aktiv.
S	No optimizations are active.	Keine Optimierungen aktiv.
S	All optimizations were reverted. Restart your PC to finish.	Alle Optimierungen wurden zur\u00fcckgesetzt. Starte deinen PC neu, um abzuschlie\u00dfen.
S	Windows could not create a restore point. Make sure System Protection is turned on for your system drive (search "Create a restore point" in Start).	Windows konnte keinen Wiederherstellungspunkt erstellen. Pr\u00fcfe, ob der Computerschutz f\u00fcr dein Systemlaufwerk eingeschaltet ist (im Start nach "Wiederherstellungspunkt erstellen" suchen).
S	Restart your PC now? Save your work first.	PC jetzt neu starten? Speichere vorher deine Arbeit.
S	Your PC is fully optimized	Dein PC ist voll optimiert
S	All safe optimizations are on. Try the Competitive preset or the Network & Input tools for even lower latency.	Alle sicheren Optimierungen sind an. Probiere das Competitive-Preset oder die Netzwerk-&-Eingabe-Tools f\u00fcr noch weniger Latenz.
S	Show me	Zeig's mir
S	Tune this PC for competitive play	Diesen PC f\u00fcr Competitive einstellen
S	Open Quick Boost	Quick Boost \u00f6ffnen
S	Everything looks great	Alles sieht super aus
S	Your hardware is healthy and all recommended optimizations are on. Enjoy the game.	Deine Hardware ist in Ordnung und alle empfohlenen Optimierungen sind an. Viel Spa\u00df beim Zocken.
S	Ultimate Performance Power Plan	Energiesparplan Ultimative Leistung
S	Unlocks and activates the hidden Ultimate Performance plan so your CPU stops down-clocking and parking cores between frames. Smoother frame times, higher idle power draw.	Schaltet den versteckten Plan "Ultimative Leistung" frei, damit deine CPU zwischen den Bildern nicht runtertaktet und keine Kerne parkt. Gleichm\u00e4\u00dfigere Frametimes, etwas mehr Stromverbrauch im Leerlauf.
S	Disable Power Throttling	Energiedrosselung aus
S	Stops Windows from throttling background processes (EcoQoS). Keeps launchers, overlays, Discord and voice chat at full speed instead of being pushed to slow states.	Verhindert, dass Windows Hintergrundprozesse drosselt (EcoQoS). Launcher, Overlays, Discord und Voice-Chat laufen mit voller Geschwindigkeit.
S	Hardware-Accelerated GPU Scheduling	Hardwarebeschleunigte GPU-Planung
S	Lets your graphics card schedule its own video memory instead of the CPU doing it. Lowers CPU overhead and render latency on modern NVIDIA, AMD and Intel GPUs.	Die Grafikkarte verwaltet ihren Videospeicher selbst statt der CPU. Weniger CPU-Last und Render-Latenz bei modernen NVIDIA-, AMD- und Intel-GPUs.
S	Enable Game Mode	Spielmodus einschalten
S	Tells Windows to prioritise the game you are playing and to hold back Windows Update installs and driver restarts while a game is running.	Windows bevorzugt dein laufendes Spiel und h\u00e4lt Windows-Update-Installationen und Treiber-Neustarts zur\u00fcck, solange ein Spiel l\u00e4uft.
S	Disable Game DVR & Background Recording	Game DVR & Hintergrundaufnahme aus
S	Turns off Xbox background capture, which constantly records gameplay and costs frames. Use NVIDIA ShadowPlay instead if you want clips.	Schaltet die Xbox-Hintergrundaufnahme aus, die st\u00e4ndig mitschneidet und FPS kostet. F\u00fcr Clips lieber NVIDIA ShadowPlay nutzen.
S	Disable Fullscreen Optimizations	Vollbildoptimierungen aus
S	Forces true exclusive fullscreen in DirectX 9/11 games for lower input latency. Alt-tab becomes slower - leave this off if you mostly play borderless.	Erzwingt echtes exklusives Vollbild in DirectX-9/11-Spielen f\u00fcr weniger Input-Lag. Alt-Tab wird langsamer - lass es aus, wenn du meist randlos spielst.
S	Prioritize Games (MMCSS)	Spiele priorisieren (MMCSS)
S	Raises the Multimedia Class Scheduler profile for games: high CPU scheduling category, high I/O priority and top GPU priority.	Erh\u00f6ht das Multimedia-Class-Scheduler-Profil f\u00fcr Spiele: hohe CPU-Kategorie, hohe E/A-Priorit\u00e4t und h\u00f6chste GPU-Priorit\u00e4t.
S	Maximize System Responsiveness	Maximale Systemreaktion
S	Reserves only 10% of CPU time for background multimedia tasks instead of 20%, giving the game more CPU time.	Reserviert nur 10 % statt 20 % CPU-Zeit f\u00fcr Multimedia im Hintergrund - das Spiel bekommt mehr CPU-Zeit.
S	Foreground Priority Boost	Vordergrund-Priorit\u00e4t
S	Uses short, variable CPU time slices with maximum boost for the foreground window (0x26), so the game gets the scheduler's attention first.	Nutzt kurze, variable CPU-Zeitscheiben mit maximalem Boost f\u00fcr das Vordergrundfenster (0x26), damit das Spiel zuerst drankommt.
S	Global Timer Resolution	Globale Timer-Aufl\u00f6sung
S	Restores system-wide high-resolution timer behaviour on Windows 11, so games that request 0.5-1 ms timers always get them. Lower frame-time jitter, slightly higher power use.	Stellt unter Windows 11 die systemweite hochaufl\u00f6sende Timer-Funktion wieder her, damit Spiele ihre 0,5-1-ms-Timer immer bekommen. Weniger Frametime-Schwankung, etwas mehr Stromverbrauch.
S	Disable CPU Core Parking	CPU-Core-Parking aus
S	Keeps all CPU cores (including E-cores on Intel hybrid CPUs) awake so game threads never wait for a parked core to wake up. Applies to the active power plan.	H\u00e4lt alle CPU-Kerne wach (auch E-Kerne bei Intel-Hybrid-CPUs), damit Spiel-Threads nie auf einen geparkten Kern warten. Gilt f\u00fcr den aktiven Energiesparplan.
S	Disable USB Selective Suspend	USB-Energiesparmodus aus
S	Prevents Windows from putting your mouse, keyboard and headset USB ports to sleep, avoiding input drop-outs and wake-up lag.	Verhindert, dass Windows die USB-Anschl\u00fcsse von Maus, Tastatur und Headset schlafen legt - keine Eingabe-Aussetzer und kein Aufwach-Lag.
S	Disable PCIe Power Saving	PCIe-Energiesparen aus
S	Turns off PCIe Link State Power Management so the graphics card and NVMe SSD links never drop into low-power states mid-game.	Schaltet die PCIe-Verbindungsstatus-Energieverwaltung aus, damit Grafikkarte und NVMe-SSD mitten im Spiel nie in den Stromsparmodus fallen.
S	Makes sure your NVIDIA graphics card uses MSI interrupts instead of legacy line-based IRQs for lower interrupt latency. Recent NVIDIA drivers often enable this already.	Sorgt daf\u00fcr, dass deine NVIDIA-Grafikkarte MSI-Interrupts statt alter IRQs nutzt - niedrigere Interrupt-Latenz. Neuere NVIDIA-Treiber machen das oft schon.
S	Disable Dynamic Tick	Dynamic Tick aus
S	Keeps the kernel timer ticking at a constant rate instead of pausing when idle. Can reduce micro-stutter and DPC latency spikes. If BitLocker is on, suspend it before restarting.	L\u00e4sst den Kernel-Timer gleichm\u00e4\u00dfig ticken statt im Leerlauf zu pausieren. Kann Mikroruckler und DPC-Latenzspitzen verringern. Wenn BitLocker an ist, vor dem Neustart anhalten.
S	Disable Memory Integrity (VBS)	Speicherintegrit\u00e4t aus (VBS)
S	Turns off Virtualization-Based Security / Core Isolation, which Microsoft itself says can cost gaming performance. This lowers protection against kernel-level malware - only do it if you accept that trade-off.	Schaltet virtualisierungsbasierte Sicherheit / Kernisolierung aus, die laut Microsoft selbst Spieleleistung kosten kann. Das senkt den Schutz vor Kernel-Malware - nur machen, wenn du das in Kauf nimmst.
S	Disable Mouse Acceleration	Mausbeschleunigung aus
S	Turns off "Enhance pointer precision" for 1:1 raw mouse movement - essential for consistent aim. Applied instantly.	Schaltet "Zeigerbeschleunigung verbessern" aus f\u00fcr 1:1-Mausbewegung - wichtig f\u00fcr konstantes Zielen. Wirkt sofort.
S	Disable Network Throttling	Netzwerkdrosselung aus
S	Removes the packet-rate cap Windows applies to non-multimedia traffic while audio or video plays. Helps against ping spikes with Discord or music running.	Entfernt die Paketraten-Grenze, die Windows bei laufendem Audio oder Video setzt. Hilft gegen Ping-Spitzen mit Discord oder Musik im Hintergrund.
S	Sends small TCP packets immediately instead of batching them. Helps TCP-based games (MMOs, some older titles); UDP shooters like Valorant or CS2 are unaffected.	Schickt kleine TCP-Pakete sofort statt sie zu sammeln. Hilft TCP-Spielen (MMOs, manche \u00e4ltere Titel); UDP-Shooter wie Valorant oder CS2 sind nicht betroffen.
S	Disable Network Adapter Power Saving	Netzwerkadapter-Energiesparen aus
S	Stops Windows from switching off your Ethernet/Wi-Fi adapter to save power, a common cause of lag spikes and short disconnects.	Verhindert, dass Windows deinen LAN-/WLAN-Adapter zum Stromsparen abschaltet - h\u00e4ufige Ursache f\u00fcr Lag-Spitzen und kurze Verbindungsabbr\u00fcche.
S	Disable Interrupt Moderation	Interrupt-Moderation aus
S	Makes the network card signal every packet immediately instead of batching them. Shaves network latency at the cost of a little CPU - modern CPUs have plenty. The connection blinks while applying.	Die Netzwerkkarte meldet jedes Paket sofort statt gesammelt. Etwas weniger Netzwerk-Latenz f\u00fcr etwas CPU - moderne CPUs haben genug. Die Verbindung blinkt beim Anwenden kurz.
S	Use Cloudflare DNS (1.1.1.1)	Cloudflare-DNS nutzen (1.1.1.1)
S	Switches your connected adapters to Cloudflare's fast public DNS for quicker lookups when connecting to game servers. Reverting restores your previous (usually router) DNS.	Stellt deine Adapter auf den schnellen \u00f6ffentlichen DNS von Cloudflare um, f\u00fcr schnellere Aufl\u00f6sung beim Verbinden mit Spielservern. Zur\u00fccksetzen stellt deinen vorherigen DNS (meist Router) wieder her.
S	Disable Update Peer Sharing	Update-Verteilung an andere PCs aus
S	Stops Windows Update from uploading updates to other PCs over the internet (Delivery Optimization), which can eat upload bandwidth mid-match.	Verhindert, dass Windows Update \u00fcber das Internet Updates an andere PCs hochl\u00e4dt (\u00dcbermittlungsoptimierung) - das kann mitten im Match Upload fressen.
S	Flush DNS Cache	DNS-Cache leeren
S	Clears cached DNS entries. Fixes "can't connect to server" problems after game server or network changes.	L\u00f6scht gespeicherte DNS-Eintr\u00e4ge. Behebt "Keine Verbindung zum Server"-Probleme nach Server- oder Netzwerkwechseln.
S	Disable Memory Compression	Speicherkomprimierung aus
S	With 16 GB or more you rarely run out of RAM, so compressing memory just burns CPU cycles. Needs the SysMain service running while you toggle it.	Mit 16 GB oder mehr geht der RAM selten aus, Komprimieren kostet dann nur CPU. Der SysMain-Dienst muss beim Umschalten laufen.
S	Disable SysMain (Superfetch)	SysMain aus (Superfetch)
S	SysMain preloads apps into RAM - pointless on a fast NVMe SSD and a known source of background disk and CPU spikes.	SysMain l\u00e4dt Apps vorab in den RAM - sinnlos auf einer schnellen NVMe-SSD und eine bekannte Quelle f\u00fcr Festplatten- und CPU-Spitzen.
S	Keep Windows Kernel in RAM	Windows-Kernel im RAM halten
S	Stops Windows from paging kernel and driver code out to disk. With 16 GB or more this costs nothing and avoids rare hitches.	Verhindert, dass Windows Kernel- und Treibercode auf die Festplatte auslagert. Mit 16 GB oder mehr kostet das nichts und vermeidet seltene H\u00e4nger.
S	Disable Hibernation	Ruhezustand aus
S	Deletes hiberfil.sys and frees several GB (about 40% of your RAM size) on your system drive. Also turns off Fast Startup.	L\u00f6scht hiberfil.sys und gibt mehrere GB (etwa 40 % deiner RAM-Gr\u00f6\u00dfe) auf dem Systemlaufwerk frei. Schaltet auch den Schnellstart aus.
S	Disable Fast Startup	Schnellstart aus
S	Makes Shut down a real shutdown so Windows and the NVIDIA driver fully reload. Fixes many "PC gets slower until I restart" issues.	Herunterfahren f\u00e4hrt wirklich herunter, damit Windows und der NVIDIA-Treiber komplett neu laden. Behebt viele "PC wird langsamer, bis ich neu starte"-Probleme.
S	Disable NTFS Last-Access Timestamps	NTFS-Zugriffszeitstempel aus
S	Stops Windows writing a timestamp every time a file is read. Fewer SSD writes while games stream thousands of asset files.	Windows schreibt nicht mehr bei jedem Lesen einer Datei einen Zeitstempel. Weniger SSD-Schreibzugriffe, wenn Spiele tausende Dateien laden.
S	Disable 8.3 Short File Names	8.3-Kurznamen aus
S	Stops NTFS creating legacy DOS-style short names for every new file, speeding up file creation in big game folders.	NTFS erstellt keine alten DOS-Kurznamen mehr f\u00fcr jede neue Datei - schnelleres Anlegen in gro\u00dfen Spielordnern.
S	Ensure SSD TRIM Is Enabled	SSD-TRIM sicher einschalten
S	Makes sure Windows tells your SSD which blocks are free, keeping write speed and lifespan at their best.	Sorgt daf\u00fcr, dass Windows deiner SSD freie Bl\u00f6cke meldet - beste Schreibgeschwindigkeit und Lebensdauer.
S	Disable Search Indexing	Suchindizierung aus
S	Stops the Windows Search indexer crawling your drive in the background. Searching for files in Start becomes slower; finding apps still works.	Der Windows-Suchindex durchsucht dein Laufwerk nicht mehr im Hintergrund. Dateisuche im Start wird langsamer; Apps finden klappt weiter.
S	Optimize SSD Now (ReTrim)	SSD jetzt optimieren (ReTrim)
S	Sends a full TRIM pass to all your SSD volumes so the controller can reclaim free blocks right away.	Schickt einen kompletten TRIM-Durchlauf an alle SSD-Laufwerke, damit freie Bl\u00f6cke sofort freigegeben werden.
S	Clean Temporary Files	Tempor\u00e4re Dateien l\u00f6schen
S	Deletes leftover files in your user and Windows temp folders. Files that are in use are skipped automatically.	L\u00f6scht Reste in deinen Benutzer- und Windows-Temp-Ordnern. Dateien in Benutzung werden automatisch \u00fcbersprungen.
S	Remove Startup App Delay	Autostart-Verz\u00f6gerung entfernen
S	Windows waits several seconds after sign-in before launching startup apps. This removes the artificial delay.	Windows wartet nach der Anmeldung einige Sekunden, bevor Autostart-Apps starten. Das entfernt diese k\u00fcnstliche Pause.
S	Instant Menus	Sofortige Men\u00fcs
S	Removes the 400 ms delay before menus and sub-menus open.	Entfernt die 400-ms-Verz\u00f6gerung, bevor Men\u00fcs und Untermen\u00fcs aufgehen.
S	Faster Shutdown	Schnelleres Herunterfahren
S	Gives hung apps and services 2 seconds instead of 5+ to close at shutdown. Save your work before shutting down, as always.	H\u00e4ngende Apps und Dienste bekommen beim Herunterfahren 2 statt 5+ Sekunden. Speichere wie immer vorher deine Arbeit.
S	Disable Windows Error Reporting	Windows-Fehlerberichte aus
S	Stops Windows collecting and uploading crash dumps after every app or game crash, which can freeze the PC for several seconds.	Windows sammelt und l\u00e4dt nach Abst\u00fcrzen keine Crash-Dumps mehr hoch - das kann den PC einige Sekunden einfrieren.
S	Disable Remote Assistance	Remoteunterst\u00fctzung aus
S	Turns off unsolicited Remote Assistance connections. One less listening service and attack surface.	Schaltet unaufgeforderte Remoteunterst\u00fctzung aus. Ein lauschender Dienst und eine Angriffsfl\u00e4che weniger.
S	Disable Transparency Effects	Transparenzeffekte aus
S	Turns off the acrylic blur in the taskbar and Start menu, removing a little constant work from the desktop compositor.	Schaltet die Unsch\u00e4rfe in Taskleiste und Startmen\u00fc aus und nimmt dem Desktop etwas Dauerarbeit ab.
S	Disable Window Animations	Fensteranimationen aus
S	Removes minimize/maximize and taskbar animations so alt-tabbing in and out of games feels instant. Takes effect after sign-out.	Entfernt Minimieren-/Maximieren- und Taskleisten-Animationen, damit Alt-Tab in und aus Spielen sofort wirkt. Wirkt nach Abmelden.
S	Disable Background Apps	Hintergrund-Apps aus
S	Stops Microsoft Store apps from running in the background when you are not using them.	Microsoft-Store-Apps laufen nicht mehr im Hintergrund, wenn du sie nicht nutzt.
S	Disable Copilot	Copilot aus
S	Hides Copilot from the taskbar and turns off the Windows Copilot integration.	Blendet Copilot in der Taskleiste aus und schaltet die Copilot-Integration ab.
S	Disable Recall & AI Snapshots	Recall & KI-Snapshots aus
S	Prevents Windows Recall from taking and analysing screenshots of everything you do.	Verhindert, dass Windows Recall Screenshots von allem macht, was du tust, und sie auswertet.
S	Disable Widgets	Widgets aus
S	Removes the Widgets board and its background news feed process (Widgets.exe / WebView2).	Entfernt das Widgets-Board und seinen News-Prozess im Hintergrund (Widgets.exe / WebView2).
S	Disable Cortana	Cortana aus
S	Turns off Cortana so it cannot run or use CPU and disk in the background.	Schaltet Cortana aus, damit sie nicht im Hintergrund CPU und Festplatte nutzt.
S	Disable Web Results in Start Search	Webergebnisse in der Startsuche aus
S	Start search only searches your PC - no Bing results, no network round-trip, faster results.	Die Startsuche durchsucht nur deinen PC - keine Bing-Ergebnisse, kein Netzwerk, schnellere Ergebnisse.
S	Remove Start Menu Ads & Auto-Installed Apps	Startmen\u00fc-Werbung & Auto-Apps entfernen
S	Stops Windows silently installing promoted apps and removes suggestions and recommendations from Start.	Windows installiert keine beworbenen Apps mehr heimlich und Vorschl\u00e4ge im Start verschwinden.
S	Remove Windows Settings Ads	Werbung in den Einstellungen entfernen
S	Removes promotional suggestions and offers from the Settings app.	Entfernt Werbevorschl\u00e4ge und Angebote aus der Einstellungen-App.
S	Disable Lock Screen Tips & Ads	Sperrbildschirm-Tipps & Werbung aus
S	Removes fun facts, tips and promotions from the lock screen.	Entfernt Fun Facts, Tipps und Werbung vom Sperrbildschirm.
S	Disable Tips & "Finish Setup" Nags	Tipps & "Einrichtung abschlie\u00dfen"-Nerven aus
S	Stops the "Let's finish setting up your device" screens and tip notifications.	Stoppt die "Lass uns die Einrichtung abschlie\u00dfen"-Bildschirme und Tipp-Benachrichtigungen.
S	Stop Edge Running in Background	Edge im Hintergrund stoppen
S	Disables Edge Startup Boost and background mode so Edge does not sit in RAM when closed. Edge will say it is "managed by your organization" - that is normal for policies.	Schaltet Edge-Startboost und Hintergrundmodus aus, damit Edge geschlossen nicht im RAM bleibt. Edge zeigt dann "Von deiner Organisation verwaltet" - das ist bei Richtlinien normal.
S	Stop OneDrive Auto-Start	OneDrive-Autostart stoppen
S	Prevents OneDrive from launching and syncing at boot. You can still open it manually any time.	OneDrive startet und synchronisiert nicht mehr beim Hochfahren. Du kannst es jederzeit manuell \u00f6ffnen.
S	Disable Xbox Services	Xbox-Dienste aus
S	Turns off Xbox Live sign-in, cloud-save and networking services. Leave this OFF if you use Game Pass, the Xbox app or Xbox cloud saves.	Schaltet Xbox-Live-Anmeldung, Cloud-Speicher und Netzwerkdienste aus. Lass das AUS, wenn du Game Pass, die Xbox-App oder Xbox-Cloud-Spielst\u00e4nde nutzt.
S	Disable Xbox Game Bar Overlay	Xbox-Game-Bar-Overlay aus
S	Stops the Win+G overlay hooking into games. Game Mode keeps working.	Das Win+G-Overlay klinkt sich nicht mehr in Spiele ein. Der Spielmodus funktioniert weiter.
S	App Cleaner: Remove Unneeded Apps	App-Cleaner: Unn\u00f6tige Apps entfernen
S	Opens the App Cleaner, where you pick exactly which preinstalled apps (News, Solitaire, Clipchamp, Candy Crush, TikTok ...) get removed.	\u00d6ffnet den App-Cleaner, wo du genau ausw\u00e4hlst, welche vorinstallierten Apps (News, Solitaire, Clipchamp, Candy Crush, TikTok ...) entfernt werden.
S	Minimize Windows Telemetry	Windows-Telemetrie minimieren
S	Sets diagnostic data to the minimum your edition allows and stops the Connected User Experiences & Telemetry service that uploads usage data in the background.	Setzt Diagnosedaten auf das Minimum deiner Edition und stoppt den Telemetrie-Dienst, der im Hintergrund Nutzungsdaten hochl\u00e4dt.
S	Disable Telemetry Scheduled Tasks	Telemetrie-Aufgaben aus
S	Disables the Compatibility Appraiser, CEIP and feedback tasks that wake up in the background and scan your PC.	Schaltet Kompatibilit\u00e4ts-, CEIP- und Feedback-Aufgaben aus, die im Hintergrund aufwachen und deinen PC scannen.
S	Disable Advertising ID	Werbe-ID aus
S	Stops apps using your advertising ID to show personalised ads across apps.	Apps nutzen deine Werbe-ID nicht mehr f\u00fcr personalisierte Werbung.
S	Disable Activity History	Aktivit\u00e4tsverlauf aus
S	Stops Windows recording and uploading a timeline of the apps and files you use.	Windows zeichnet keinen Verlauf deiner Apps und Dateien mehr auf und l\u00e4dt ihn nicht hoch.
S	Disable Tailored Experiences	Ma\u00dfgeschneiderte Erfahrungen aus
S	Stops Microsoft using your diagnostic data to show personalised tips, ads and recommendations.	Microsoft nutzt deine Diagnosedaten nicht mehr f\u00fcr personalisierte Tipps, Werbung und Empfehlungen.
S	Disable Feedback Prompts	Feedback-Abfragen aus
S	No more "How likely are you to recommend Windows?" pop-ups.	Keine "Wie wahrscheinlich empfehlen Sie Windows?"-Pop-ups mehr.
S	Disable NVIDIA Telemetry	NVIDIA-Telemetrie aus
S	Opts out of NVIDIA driver telemetry and stops the NVIDIA telemetry container service if your driver has one.	Meldet dich von der NVIDIA-Treiber-Telemetrie ab und stoppt den Telemetrie-Dienst, falls dein Treiber einen hat.
S	Disable Firefox Telemetry	Firefox-Telemetrie aus
S	Stops Firefox sending usage and performance data to Mozilla.	Firefox sendet keine Nutzungs- und Leistungsdaten mehr an Mozilla.
S	Disable Location Access	Standortzugriff aus
S	Blocks all apps from using your location. Automatic time zone and local weather will stop working.	Sperrt allen Apps den Standort. Automatische Zeitzone und lokales Wetter funktionieren dann nicht mehr.
S	Disable Sticky Keys Pop-up	Einrastfunktion-Pop-up aus
S	No more Sticky Keys pop-up when you tap Shift five times mid-game. Also disables the Filter Keys and Toggle Keys shortcuts.	Kein Einrastfunktion-Pop-up mehr, wenn du im Spiel f\u00fcnfmal Shift dr\u00fcckst. Schaltet auch die Tastenk\u00fcrzel f\u00fcr Anschlagverz\u00f6gerung und Statustasten aus.
S	Fastest Keyboard Repeat	Schnellste Tastenwiederholung
S	Shortest delay before a held key starts repeating, at the fastest repeat rate. Takes effect after sign-out.	K\u00fcrzeste Verz\u00f6gerung, bevor eine gehaltene Taste wiederholt, mit schnellster Rate. Wirkt nach Abmelden.
S	Show Detailed Boot Messages	Detaillierte Startmeldungen zeigen
S	Shows what Windows is doing during startup and shutdown. Does not speed things up, but makes hangs easy to diagnose.	Zeigt, was Windows beim Starten und Herunterfahren macht. Macht nichts schneller, aber H\u00e4nger leicht erkennbar.
S	Show File Extensions	Dateiendungen anzeigen
S	Always show .exe, .zip, .cfg and other extensions - handy when editing game configs and safer against fake files.	Zeigt immer .exe, .zip, .cfg und andere Endungen - praktisch f\u00fcr Spiel-Configs und sicherer gegen gef\u00e4lschte Dateien.
S	Classic Right-Click Menu	Klassisches Rechtsklick-Men\u00fc
S	Brings back the full Windows 10 right-click menu without the extra "Show more options" click. Explorer restarts automatically.	Holt das volle Windows-10-Rechtsklickmen\u00fc zur\u00fcck, ohne den Extra-Klick auf "Weitere Optionen anzeigen". Der Explorer startet automatisch neu.
S	Open Explorer to This PC	Explorer \u00f6ffnet "Dieser PC"
S	File Explorer opens straight to your drives instead of Home / Quick access.	Der Explorer \u00f6ffnet direkt deine Laufwerke statt Start / Schnellzugriff.
S	Hide Recent Files in Quick Access	Zuletzt verwendete Dateien ausblenden
S	Stops Explorer listing recently opened files and frequent folders.	Der Explorer listet keine zuletzt ge\u00f6ffneten Dateien und h\u00e4ufigen Ordner mehr.
S	Group Windows Services (fewer svchost)	Windows-Dienste gruppieren (weniger svchost)
S	With more than 3.5 GB RAM Windows starts every service in its own svchost.exe. Grouping them again removes roughly 30-80 processes after a restart. Trade-off: if one service crashes, its group restarts with it.	Mit mehr als 3,5 GB RAM startet Windows jeden Dienst in einer eigenen svchost.exe. Gruppieren spart nach einem Neustart etwa 30-80 Prozesse. Nachteil: St\u00fcrzt ein Dienst ab, startet seine Gruppe mit neu.
S	Disable Unneeded Services	Unn\u00f6tige Dienste aus
S	Turns off services almost no gaming PC needs: Fax, Remote Registry, Offline Maps, Retail Demo, Windows Insider, Media Player network sharing, Link Tracking, Parental Controls, NFC Payments and the Program Compatibility Assistant.	Schaltet Dienste aus, die fast kein Gaming-PC braucht: Fax, Remoteregistrierung, Offlinekarten, Retail-Demo, Windows Insider, Media-Player-Netzwerkfreigabe, Verkn\u00fcpfungsverfolgung, Jugendschutz, NFC-Zahlungen und den Programmkompatibilit\u00e4ts-Assistenten.
S	Disable Print Spooler	Druckwarteschlange aus
S	Stops the printing service. Only do this if you do not use a printer - turn it back on any time you need to print.	Stoppt den Druckdienst. Nur machen, wenn du keinen Drucker nutzt - zum Drucken jederzeit wieder einschalten.
S	Disable Network Adapter Energy Saving	Netzwerkadapter-Energiesparfunktionen aus
S	Turns off Energy-Efficient Ethernet, Green Ethernet and similar adapter power features that put the link to sleep between packets and cause small ping spikes. The connection drops for a few seconds while applying.	Schaltet Energy-Efficient Ethernet, Green Ethernet und \u00e4hnliche Funktionen aus, die die Verbindung zwischen Paketen schlafen legen und kleine Ping-Spitzen verursachen. Die Verbindung ist beim Anwenden ein paar Sekunden weg.
S	Disable Large Send Offload	Large Send Offload aus
S	Stops the network card from collecting outgoing data into big chunks before sending. Small game packets leave right away. The connection drops for a few seconds while applying.	Die Netzwerkkarte sammelt ausgehende Daten nicht mehr in gro\u00dfe Bl\u00f6cke. Kleine Spielpakete gehen sofort raus. Die Verbindung ist beim Anwenden ein paar Sekunden weg.
S	Prioritize Game Traffic (QoS)	Spiel-Datenverkehr priorisieren (QoS)
S	Marks the network packets of all known games (and your own added games) as top priority (DSCP 46). Wi-Fi and routers that support QoS / WMM send them first when the connection is busy.	Markiert die Netzwerkpakete aller bekannten Spiele (und deiner eigenen) als h\u00f6chste Priorit\u00e4t (DSCP 46). WLAN und Router mit QoS / WMM schicken sie bei voller Leitung zuerst.
S	Limit Background Update Downloads	Update-Downloads im Hintergrund begrenzen
S	Windows Update and Store downloads in the background may use at most 10% of your bandwidth, so they cannot flood your connection and spike your ping mid-match.	Windows-Update- und Store-Downloads im Hintergrund d\u00fcrfen h\u00f6chstens 10 % deiner Bandbreite nutzen und k\u00f6nnen so mitten im Match nicht deinen Ping hochtreiben.
S	Disable Receive Segment Coalescing	Receive Segment Coalescing aus
S	Stops the network card from holding incoming packets back to merge them into bigger chunks. Game packets reach the game immediately instead of waiting to be bundled.	Die Netzwerkkarte h\u00e4lt eingehende Pakete nicht mehr zum B\u00fcndeln zur\u00fcck. Spielpakete kommen sofort im Spiel an.
S	Enable Receive Side Scaling	Receive Side Scaling an
S	Lets several CPU cores process incoming network traffic instead of one, so a busy core never delays your game packets.	Mehrere CPU-Kerne verarbeiten eingehenden Netzwerkverkehr statt nur einer, damit ein ausgelasteter Kern deine Spielpakete nie bremst.
S	Maximum Network Buffers (no packet drops)	Maximale Netzwerkpuffer (kein Paketverlust)
S	Sets the receive and transmit buffers of your network card to the maximum, so bursts of traffic (downloads, voice chat, game updates) never cause dropped packets. Uses a few MB of RAM. The connection drops for a few seconds while applying.	Setzt die Empfangs- und Sendepuffer deiner Netzwerkkarte auf das Maximum, damit Verkehrsspitzen (Downloads, Voice-Chat, Updates) nie Pakete verlieren. Braucht ein paar MB RAM. Die Verbindung ist beim Anwenden ein paar Sekunden weg.
S	Wi-Fi: Lowest Roaming Aggressiveness	WLAN: Niedrigste Roaming-Aggressivit\u00e4t
S	Stops your Wi-Fi card from constantly scanning for a "better" access point - those background scans cause the classic ping spike every 30-60 seconds. The connection drops for a few seconds while applying.	Deine WLAN-Karte sucht nicht mehr st\u00e4ndig nach einem "besseren" Zugangspunkt - diese Scans verursachen die typische Ping-Spitze alle 30-60 Sekunden. Die Verbindung ist beim Anwenden ein paar Sekunden weg.
S	Disable Ethernet Flow Control	Ethernet-Flusskontrolle aus
S	Stops the network card and router from sending "pause" frames that briefly halt traffic. Can remove tiny delays on a busy LAN; on rare setups it causes more packet loss - turn it back off if your ping gets worse.	Netzwerkkarte und Router senden keine "Pause"-Frames mehr, die den Verkehr kurz anhalten. Kann kleine Verz\u00f6gerungen im vollen LAN entfernen; selten gibt es mehr Paketverlust - dann wieder ausschalten.
S	Optimizations for Windowed Games	Optimierungen f\u00fcr Spiele im Fenstermodus
S	Windows 11 feature: DirectX 10/11 games in borderless or windowed mode use the modern flip presentation model - lower input lag, close to exclusive fullscreen.	Windows-11-Funktion: DirectX-10/11-Spiele im randlosen oder Fenstermodus nutzen das moderne Flip-Modell - weniger Input-Lag, fast wie exklusives Vollbild.
S	Disable Power Saving on USB & Input Devices	Energiesparen bei USB- & Eingabeger\u00e4ten aus
S	Turns off "Allow the computer to turn off this device to save power" for every USB controller, hub, mouse, keyboard and HID device - no more wake-up delay or dropped inputs.	Schaltet "Computer kann das Ger\u00e4t ausschalten, um Energie zu sparen" f\u00fcr jeden USB-Controller, Hub, Maus, Tastatur und jedes HID-Ger\u00e4t aus - keine Aufwach-Verz\u00f6gerung und keine verlorenen Eingaben.
S	Use the Fast CPU Timer (no forced HPET)	Schnellen CPU-Timer nutzen (kein erzwungenes HPET)
S	Some old tweak tools force Windows onto the slow HPET timer (useplatformclock), which adds latency and costs FPS. This removes that setting so Windows uses the fast built-in CPU timer. Shows as active when your PC is already correct.	Manche alten Tweak-Tools zwingen Windows auf den langsamen HPET-Timer (useplatformclock) - das kostet Latenz und FPS. Das entfernt die Einstellung, damit Windows den schnellen CPU-Timer nutzt. Zeigt aktiv, wenn dein PC schon richtig eingestellt ist.
S	Mouse Pointer Speed 6/11 (1:1)	Mauszeiger-Tempo 6/11 (1:1)
S	Sets the Windows pointer speed to the 6th notch, the only setting where one mouse count moves the cursor exactly one pixel. Games that do not use raw input then feel exactly like your mouse DPI. Your desktop cursor speed may change.	Setzt das Windows-Zeigertempo auf Stufe 6 - die einzige Stufe, bei der ein Maus-Count den Zeiger genau einen Pixel bewegt. Spiele ohne Raw Input f\u00fchlen sich dann genau wie deine Maus-DPI an. Dein Desktop-Zeigertempo kann sich \u00e4ndern.
S	FPS & Latency	FPS & Latenz
S	Network & Ping	Netzwerk & Ping
S	Input	Eingabe
S	Memory & Storage	Speicher & Laufwerke
S	Privacy	Privatsph\u00e4re
S	Quality of Life	Komfort
S	Welcome to Silvan Boost	Willkommen bei Silvan Boost
S	Your PC is scanned. A short tour shows you the few buttons that matter most.	Dein PC ist gescannt. Eine kurze Tour zeigt dir die paar Kn\u00f6pfe, auf die es ankommt.
S	LANGUAGE	SPRACHE
S	Applies instantly. No restart needed.	Wirkt sofort. Kein Neustart n\u00f6tig.
S	Start the tour (1 min)	Tour starten (1 Min.)
S	Skip	\u00dcberspringen
S	You can open the tour again any time with the ? button.	Mit dem ?-Knopf kannst du die Tour jederzeit wieder \u00f6ffnen.
S	Skip tour	Tour \u00fcberspringen
S	Back	Zur\u00fcck
S	Finish	Fertig
S	Your PC score	Dein PC-Score
S	This shows how optimized your PC is. The card below always names the one next step worth doing.	Hier siehst du, wie gut dein PC optimiert ist. Die Karte darunter nennt immer den n\u00e4chsten sinnvollen Schritt.
S	The one button most people need. Pick Competitive - a restore point is made for you.	Der eine Knopf, den die meisten brauchen. W\u00e4hle Competitive - ein Wiederherstellungspunkt wird automatisch erstellt.
S	Pick your game, then click Optimize.	W\u00e4hle dein Spiel und klicke dann auf Optimieren.
S	Leave Silvan Boost open while you play (minimized is fine). Problems show up with a fix.	Lass Silvan Boost beim Spielen offen (minimiert reicht). Probleme erscheinen mit L\u00f6sung.
S	Ping Booster, Input Lag and game-safe Macros live here.	Hier findest du Ping-Booster, Input-Lag und spielsichere Makros.
S	Safety first	Sicherheit zuerst
S	Everything can be undone. Backup & Restore has a Revert all button.	Alles l\u00e4sst sich r\u00fcckg\u00e4ngig machen. Unter Sicherung & Wiederherstellung gibt es "Alles zur\u00fccksetzen".
S	You're all set	Alles bereit
S	New here? Do these three things, in this order:	Neu hier? Mach diese drei Dinge, in dieser Reihenfolge:
S	Quick Boost on Competitive	Quick Boost auf Competitive
S	Turns on the tweaks most people need.	Schaltet die Tweaks ein, die die meisten brauchen.
S	Game Preset for your game	Spiel-Preset f\u00fcr dein Spiel
S	Restart your PC	PC neu starten
S	Some changes only apply after a restart.	Manche \u00c4nderungen wirken erst nach einem Neustart.
S	Open the tour again any time with the ? button	Die Tour jederzeit mit dem ?-Knopf wieder \u00f6ffnen
S	Show the tour again	Tour noch mal zeigen
S	Language	Sprache
S	Changes all text right away. No restart needed.	\u00c4ndert sofort alle Texte. Kein Neustart n\u00f6tig.
S	Beginner tour	Einsteiger-Tour
S	Six short steps, about one minute. Also on the ? button up top.	Sechs kurze Schritte, etwa eine Minute. Auch \u00fcber den ?-Knopf oben.
S	Help: show the tour	Hilfe: Tour anzeigen
S	Change language	Sprache \u00e4ndern
S	Before / after benchmark	Vorher/Nachher-Benchmark
S	See what the boost really does: measure a game before and after, then share the result.	Sieh, was der Boost wirklich bringt: Miss ein Spiel vorher und nachher und teile das Ergebnis.
S	Measure before	Vorher messen
S	Click Start, then play your game for 2 minutes like you normally do.	Klicke auf Start und spiele dann 2 Minuten ganz normal.
S	Start measuring	Messung starten
S	Boost	Boosten
S	Apply Quick Boost - Competitive is recommended. Then restart your PC.	Wende Quick Boost an - Competitive wird empfohlen. Starte danach deinen PC neu.
S	Measure after	Nachher messen
S	Play the same game, same mode and same settings for 2 minutes.	Spiele dasselbe Spiel, denselben Modus mit denselben Einstellungen 2 Minuten lang.
S	Stop now	Jetzt stoppen
S	Finish now	Jetzt beenden
S	Cancel	Abbrechen
S	Save as image	Als Bild speichern
S	Start over	Neu beginnen
S	Measure again	Neu messen
S	TIPS FOR A FAIR TEST	TIPPS F\u00dcR EINEN FAIREN TEST
S	Use the same game, map or mode and the same in-game settings both times. Practice range or creative mode works best. Silvan Boost must stay open (minimized is fine). Measuring starts as soon as the game is detected - nothing is injected into the game.	Nutze beide Male dasselbe Spiel, dieselbe Map oder denselben Modus und dieselben Ingame-Einstellungen. Am besten Schie\u00dfstand oder Kreativmodus. Silvan Boost muss offen bleiben (minimiert reicht). Die Messung startet, sobald das Spiel erkannt wird - es wird nichts ins Spiel injiziert.
S	Measure "before" first.	Miss zuerst "vorher".
S	Benchmark cancelled - at least 30 seconds of gameplay are needed.	Benchmark abgebrochen - mindestens 30 Sekunden Spielzeit sind n\u00f6tig.
S	Before-measurement done. Now apply Quick Boost and restart your PC.	Vorher-Messung fertig. Wende jetzt Quick Boost an und starte deinen PC neu.
S	Benchmark done - your result is ready.	Benchmark fertig - dein Ergebnis ist da.
S	Please play the same game as before:	Bitte spiele dasselbe Spiel wie vorher:
S	Game closed - start it again to continue	Spiel geschlossen - starte es erneut, um weiterzumachen
S	Start your game now - measuring begins as soon as it is detected.	Starte jetzt dein Spiel - die Messung beginnt, sobald es erkannt wird.
S	Waiting for frames from	Warte auf Bilder von
S	Measuring	Messe
S	Play normally - you can leave Silvan Boost minimized.	Spiel ganz normal - Silvan Boost kann minimiert bleiben.
S	Do step 1 first.	Mach zuerst Schritt 1.
S	Restart the game after boosting, ideally the whole PC.	Starte nach dem Boost das Spiel neu, am besten den ganzen PC.
S	AVERAGE FPS	DURCHSCHNITT FPS
S	Your PC runs this game better after the boost. Smoother 1% lows matter most - they are what you feel as stutter.	Dein PC l\u00e4uft mit diesem Spiel nach dem Boost besser. Am wichtigsten sind die 1% Lows - die sp\u00fcrst du als Ruckler.
S	The result is lower than before. Make sure you tested the same scene and settings - or check the Live Monitor for problems.	Das Ergebnis ist schlechter als vorher. Pr\u00fcfe, ob du dieselbe Szene und Einstellungen getestet hast - oder schau im Live-Monitor nach Problemen.
S	About the same as before - your PC was already well tuned. Check the PC Scanner for bigger wins like XMP or the monitor refresh rate.	Ungef\u00e4hr wie vorher - dein PC war schon gut eingestellt. Im PC-Scanner findest du gr\u00f6\u00dfere Hebel wie XMP oder die Bildwiederholrate.
S	Image saved:	Bild gespeichert:
S	Auto game mode	Automatischer Spielmodus
S	When a game starts, the game gets high priority, browsers and launchers in the background get low priority and downloads pause. Everything goes back when you close the game.	Wenn ein Spiel startet, bekommt es hohe Priorit\u00e4t, Browser und Launcher im Hintergrund niedrige, und Downloads pausieren. Nach dem Spiel wird alles zur\u00fcckgestellt.
S	Game mode on for	Spielmodus an f\u00fcr
S	FPS history	FPS-Verlauf
S	Average FPS	Durchschnitt FPS
S	1% low	1% Low
S	Play a game for at least one minute and your sessions show up here - so you can see if a game or driver update cost you FPS.	Spiel mindestens eine Minute, dann erscheinen deine Sessions hier - so siehst du, ob ein Spiel- oder Treiber-Update FPS gekostet hat.
S	last:	zuletzt:
S	vs. your average	zu deinem Schnitt
S	Write these settings straight into the game	Diese Einstellungen direkt ins Spiel schreiben
S	Your current game config is backed up first. Close the game before applying.	Deine aktuelle Spiel-Config wird vorher gesichert. Schlie\u00dfe das Spiel vor dem \u00dcbernehmen.
S	Apply to game	Ins Spiel \u00fcbernehmen
S	Settings file not found - start the game once, then come back.	Einstellungsdatei nicht gefunden - starte das Spiel einmal und komm dann zur\u00fcck.
S	Pro settings applied. Undo brings back your old settings.	Pro-Einstellungen \u00fcbernommen. R\u00fcckg\u00e4ngig holt deine alten Einstellungen zur\u00fcck.
S	Please close the game first - it overwrites its settings when it exits.	Bitte schlie\u00dfe zuerst das Spiel - es \u00fcberschreibt seine Einstellungen beim Beenden.
S	The game settings file was not found. Start the game once, change any setting, close it - then try again.	Die Einstellungsdatei des Spiels wurde nicht gefunden. Starte das Spiel einmal, \u00e4ndere irgendeine Einstellung, schlie\u00dfe es - und versuche es dann erneut.
S	Write the pro settings into the game config now?	Pro-Einstellungen jetzt in die Spiel-Config schreiben?
S	Your current settings are backed up and can be restored with Undo.	Deine aktuellen Einstellungen werden gesichert und lassen sich mit R\u00fcckg\u00e4ngig wiederherstellen.
S	pro settings written to the game config.	Pro-Einstellungen in die Spiel-Config geschrieben.
S	{0} settings changed, {1} were already right.	{0} Einstellungen ge\u00e4ndert, {1} waren schon richtig.
S	Resolution, display mode and Reflex can still be checked in the game menu.	Aufl\u00f6sung, Anzeigemodus und Reflex kannst du noch im Spielmen\u00fc pr\u00fcfen.
S	your previous game settings are back.	deine vorherigen Spiel-Einstellungen sind zur\u00fcck.
S	Share your setup	Setup teilen
S	Save your optimizations and macros as a file and send it to a friend - they load it with one click. Only safe optimizations are imported, and a restore point is made first.	Speichere deine Optimierungen und Makros als Datei und schick sie einem Freund - er l\u00e4dt sie mit einem Klick. Es werden nur sichere Optimierungen \u00fcbernommen, und vorher wird ein Wiederherstellungspunkt erstellt.
S	Export my setup	Mein Setup exportieren
S	Import a setup	Setup importieren
S	Setup saved:	Setup gespeichert:
S	This is not a valid Silvan Boost setup file.	Das ist keine g\u00fcltige Silvan-Boost-Setup-Datei.
S	Import this setup?	Dieses Setup importieren?
S	{0} optimizations to turn on	{0} Optimierungen werden eingeschaltet
S	{0} skipped (advanced or not suitable for this PC)	{0} \u00fcbersprungen (fortgeschritten oder nicht passend f\u00fcr diesen PC)
S	{0} macro profiles, {1} macros	{0} Makro-Profile, {1} Makros
S	Applying optimizations...	Optimierungen werden angewendet...
S	Setup imported.	Setup importiert.
S	Keep running in the tray when closed	Beim Schlie\u00dfen im Infobereich weiterlaufen
S	The X button hides Silvan Boost next to the clock, so auto game mode, macros and the live monitor keep working. Right-click the tray icon to exit.	Das X versteckt Silvan Boost neben der Uhr, damit Spielmodus, Makros und Live-Monitor weiterlaufen. Zum Beenden Rechtsklick auf das Symbol.
S	Report a problem	Problem melden
S	Something not working?	Funktioniert etwas nicht?
S	Creates a short report (version, PC parts, activity log) on your desktop and copies it - send it to Silvan.	Erstellt einen kurzen Bericht (Version, PC-Teile, Aktivit\u00e4tsprotokoll) auf deinem Desktop und kopiert ihn - schick ihn an Silvan.
S	The report is on your desktop (SilvanBoost-Report.txt) and copied to the clipboard. Send it to Silvan and describe what went wrong.	Der Bericht liegt auf deinem Desktop (SilvanBoost-Report.txt) und ist kopiert. Schick ihn an Silvan und beschreib, was schiefging.
S	Open Silvan Boost	Silvan Boost \u00f6ffnen
S	Exit	Beenden
S	Still running next to the clock. Right-click the icon to exit.	L\u00e4uft weiter neben der Uhr. Zum Beenden Rechtsklick auf das Symbol.
S	Graphics driver is up to date	Grafiktreiber ist aktuell
S	Update your graphics driver	Grafiktreiber aktualisieren
P	^Not available: (.*)$	Nicht verf\u00fcgbar: $1
P	^Not recommended: (.*)$	Nicht empfohlen: $1
P	^You have the latest version \\((.*)\\) - checked (.*)\\.$	Du hast die neueste Version ($1) - gepr\u00fcft $2.
P	^Could not check for updates \\((.*)\\)\\.$	Konnte nicht nach Updates suchen ($1).
P	^Version (\\S+) is available\\.$	Version $1 ist verf\u00fcgbar.
P	^Version (\\S+)  -  (\\d+) optimizations and tools$	Version $1  -  $2 Optimierungen und Werkzeuge
P	^v(\\S+)  -  FPS Optimizer$	v$1  -  FPS-Optimierer
P	^Close selected \\((\\d+)\\)$	Ausgew\u00e4hlte schlie\u00dfen ($1)
P	^Remove selected \\((\\d+)\\)$	Ausgew\u00e4hlte entfernen ($1)
P	^Closed (\\d+) process\\(es\\)$	$1 Prozess(e) geschlossen
P	^Active now: (.*)  -  game safe mode$	Gerade aktiv: $1  -  spielsicherer Modus
P	^Active now: (.*)$	Gerade aktiv: $1
P	^Profile: (.*)$	Profil: $1
P	^Keyboard hotkey  -  profile (.*)$	Tastatur-Hotkey  -  Profil $1
P	^Mouse button  -  profile (.*)$	Maustaste  -  Profil $1
P	^(\\d+) actions$	$1 Aktionen
P	^(\\d+) steps  -  about (.*) s per run$	$1 Schritte  -  etwa $2 s pro Durchlauf
P	^Recording - (\\d+) steps so far\\. Press keys or click in any window\\. Click Stop when done\\.$	Aufnahme - bisher $1 Schritte. Dr\u00fccke Tasten oder klicke in einem beliebigen Fenster. Klicke auf Stopp, wenn du fertig bist.
P	^Wireless receiver  -  click the name to rename$	Funk-Empf\u00e4nger  -  Name anklicken zum Umbenennen
P	^USB  -  click the name to rename$	USB  -  Name anklicken zum Umbenennen
P	^Bluetooth  -  click the name to rename$	Bluetooth  -  Name anklicken zum Umbenennen
P	^Step (\\d+) of (\\d+)$	Schritt $1 von $2
P	^FPS & Latency(\\s+\\d+)$	FPS & Latenz$1
P	^Network & Ping(\\s+\\d+)$	Netzwerk & Ping$1
P	^Input(\\s+\\d+)$	Eingabe$1
P	^Memory & Storage(\\s+\\d+)$	Speicher & Laufwerke$1
P	^Processes(\\s+\\d+)$	Prozesse$1
P	^Registry(\\s+\\d+)$	Registry$1
P	^Debloat(\\s+\\d+)$	Debloat$1
P	^Privacy(\\s+\\d+)$	Privatsph\u00e4re$1
P	^Quality of Life(\\s+\\d+)$	Komfort$1
P	^Key: (.*)$	Taste: $1
P	^Open (.+)$	$1 \u00f6ffnen
P	^input to display (\\S+) ms$	Eingabe bis Bild $1 ms
P	^busiest core (\\S+)%$	st\u00e4rkster Kern $1%
P	^VRAM of (\\S+) GB  \\|  RAM (\\S+)%$	VRAM von $1 GB  |  RAM $2%
P	^loss (\\S+)%  \\|  max (\\S+) ms$	Verlust $1%  |  max $2 ms
P	^to 1\\.1\\.1\\.1  \\|  best (\\S+) ms$	zu 1.1.1.1  |  bester $1 ms
P	^jitter (\\S+) ms$	Jitter $1 ms
P	^Idle ping: (\\S+) ms$	Ping im Leerlauf: $1 ms
P	^Ping under load: (\\S+) ms  \\(\\+(\\S+) ms\\)$	Ping unter Last: $1 ms  (+$2 ms)
P	^Download during test: (\\S+) Mbit/s$	Download beim Test: $1 Mbit/s
P	^Driver (\\S+) \\((.+)\\): (\\d+) months old - newer drivers often bring FPS fixes for new games\\. Open the NVIDIA App, go to Drivers and click Download\\. If you had crashes, choose \\"Clean install\\"\\.$	Treiber $1 ($2): $3 Monate alt - neuere Treiber bringen oft FPS-Verbesserungen f\u00fcr neue Spiele. \u00d6ffne die NVIDIA App, geh zu Treiber und klicke auf Herunterladen. Wenn du Abst\u00fcrze hattest, w\u00e4hle "Neuinstallation".
P	^Driver (\\S+) \\((.+)\\): (\\d+) months old - newer drivers often bring FPS fixes for new games\\. Open AMD Software: Adrenalin Edition and click Check for updates\\.$	Treiber $1 ($2): $3 Monate alt - neuere Treiber bringen oft FPS-Verbesserungen f\u00fcr neue Spiele. \u00d6ffne AMD Software: Adrenalin Edition und klicke auf Nach Updates suchen.
P	^Driver (\\S+) \\((.+)\\): (\\d+) months old - newer drivers often bring FPS fixes for new games\\. Get the newest driver from your graphics card or laptop maker\\.$	Treiber $1 ($2): $3 Monate alt - neuere Treiber bringen oft FPS-Verbesserungen f\u00fcr neue Spiele. Hol dir den neuesten Treiber vom Hersteller deiner Grafikkarte oder deines Laptops.
P	^Driver (\\S+) from (.+)\\.$	Treiber $1 vom $2.
S	Checking your account...	Konto wird gepr\u00fcft ...
S	Try again	Erneut versuchen
S	Sign in with another account	Mit anderem Konto anmelden
S	Welcome back	Willkommen zur\u00fcck
S	Sign in to use Silvan Boost.	Melde dich an, um Silvan Boost zu nutzen.
S	USERNAME	BENUTZERNAME
S	PASSWORD	PASSWORT
S	REPEAT	WIEDERHOLEN
S	Stay signed in	Angemeldet bleiben
S	Sign in	Anmelden
S	No account yet? Create account	Noch kein Konto? Konto erstellen
S	Create account	Konto erstellen
S	Silvan unlocks your account afterwards.	Silvan schaltet dein Konto danach frei.
S	YOUR PC-ID	DEINE PC-ID
S	I already have an account	Ich habe schon ein Konto
S	Almost there	Fast geschafft
S	Silvan got your request and still has to unlock you.	Silvan hat deine Anfrage bekommen und muss dich noch freischalten.
S	Account created	Konto erstellt
S	Request sent to Silvan	Anfrage an Silvan geschickt
S	Waiting for approval...	Warte auf Freischaltung ...
S	You can close Silvan Boost and come back later.	Du kannst Silvan Boost schlie\u00dfen und sp\u00e4ter wiederkommen.
S	Sign out	Abmelden
S	You're unlocked	Du bist freigeschaltet
S	YOUR PLAN	DEIN ABO
S	Let's go	Los geht's
S	1 month	1 Monat
S	Lifetime	Lifetime
S	never ends	l\u00e4uft nie ab
S	Your plan has ended	Dein Abo ist abgelaufen
S	Waiting for renewal...	Warte auf Verl\u00e4ngerung ...
S	Message Silvan so he can extend it. The app opens again by itself.	Schreib Silvan, damit er verl\u00e4ngert. Die App \u00f6ffnet sich dann von selbst wieder.
S	This account is locked	Dieses Konto ist gesperrt
S	Wrong PC	Falscher PC
S	This account was created on a different PC.	Dieses Konto wurde auf einem anderen PC erstellt.
S	Your account only works on the PC where you created it. New PC? Ask Silvan to reset your account, then sign in here again.	Dein Konto gilt nur f\u00fcr den PC, auf dem du es erstellt hast. Neuer PC? Bitte Silvan, dein Konto zur\u00fcckzusetzen, und melde dich dann hier erneut an.
S	Request declined	Anfrage abgelehnt
S	Silvan did not approve this account. If you think this is a mistake, message him.	Silvan hat dieses Konto nicht freigeschaltet. Wenn du denkst, das ist ein Fehler, schreib ihm.
S	Silvan has ended access for this account. If you think this is a mistake, message him.	Silvan hat den Zugang f\u00fcr dieses Konto beendet. Wenn du denkst, das ist ein Fehler, schreib ihm.
S	Wrong username or password.	Falscher Benutzername oder falsches Passwort.
S	This account belongs to a different PC. It only works on the PC where it was created - ask Silvan to reset it.	Dieses Konto geh\u00f6rt zu einem anderen PC. Es funktioniert nur auf dem PC, auf dem es erstellt wurde - bitte Silvan, es zur\u00fcckzusetzen.
S	This username is already taken. Try another one.	Dieser Benutzername ist schon vergeben. Probiere einen anderen.
S	Username: 3 to 20 characters, only letters, numbers and _ . -	Benutzername: 3 bis 20 Zeichen, nur Buchstaben, Zahlen und _ . -
S	Your password needs at least 6 characters.	Dein Passwort braucht mindestens 6 Zeichen.
S	Too many tries. Wait a few minutes and try again.	Zu viele Versuche. Warte ein paar Minuten und probiere es erneut.
S	Can't reach the Silvan Boost server. Check your internet connection and try again.	Der Silvan-Boost-Server ist nicht erreichbar. Pr\u00fcfe deine Internetverbindung und probiere es erneut.
S	Enter your username and password.	Gib Benutzername und Passwort ein.
S	The two passwords are not the same.	Die beiden Passw\u00f6rter stimmen nicht \u00fcberein.
S	Signing in...	Anmeldung l\u00e4uft ...
S	Creating account...	Konto wird erstellt ...
S	You were signed out. Please sign in again.	Du wurdest abgemeldet. Bitte melde dich erneut an.
S	Not signed in	Nicht angemeldet
S	Your plan ends today. Message Silvan if you want to extend it.	Dein Abo l\u00e4uft heute ab. Schreib Silvan, wenn du verl\u00e4ngern m\u00f6chtest.
S	Your plan ends in 1 day. Message Silvan if you want to extend it.	Dein Abo l\u00e4uft in 1 Tag ab. Schreib Silvan, wenn du verl\u00e4ngern m\u00f6chtest.
P	^Almost there, (.+)$	Fast geschafft, $1
P	^Have fun with Silvan Boost, (.+)\\.$	Viel Spa\u00df mit Silvan Boost, $1.
P	^until (\\d\\d\\.\\d\\d\\.\\d{4})$	bis $1
P	^Your month of Silvan Boost ended on (.+)\\. Message Silvan so he can extend it\\. The app opens again by itself\\.$	Dein Monat Silvan Boost ist am $1 zu Ende gegangen. Schreib Silvan, damit er verl\u00e4ngert. Die App \u00f6ffnet sich dann von selbst wieder.
P	^Account (.+) \u00b7 Lifetime$	Konto $1 \u00b7 Lifetime
P	^Account (.+) \u00b7 1 day left$	Konto $1 \u00b7 noch 1 Tag
P	^Account (.+) \u00b7 (\\d+) days left$	Konto $1 \u00b7 noch $2 Tage
P	^Your plan ends in (\\d+) days\\. Message Silvan if you want to extend it\\.$	Dein Abo l\u00e4uft in $1 Tagen ab. Schreib Silvan, wenn du verl\u00e4ngern m\u00f6chtest.
P	^Something went wrong on the server \\(error (\\d+)\\)\\. Try again in a moment\\.$	Auf dem Server ist etwas schiefgelaufen (Fehler $1). Probiere es gleich noch einmal.
P	^Signed in as (.+)$	Angemeldet als $1
'@

# ------------------------------------------------------------------ language + beginner tour
function L([string]$s) { [SBLang]::Tr($s) }

function Import-LangData {
    foreach ($line in ($LangData -split "`n")) {
        $line = $line.TrimEnd("`r")
        if (-not $line) { continue }
        $p = $line.Split("`t")
        try {
            if ($p[0] -eq 'P' -and $p.Count -ge 3) { [SBLang]::AddPattern([regex]::Unescape($p[1]), [regex]::Unescape($p[2])) }
            elseif ($p[0] -eq 'S' -and $p.Count -ge 3) { [SBLang]::Add([regex]::Unescape($p[1]), [regex]::Unescape($p[2])) }
        } catch { }
    }
}

function Get-DefaultLang {
    try { if ((Get-UICulture).TwoLetterISOLanguageName -eq 'de') { return 'de' } } catch { }
    'en'
}

$script:LangSync = $false
function Set-AppLang([string]$lang, [switch]$NoSave) {
    if ($lang -ne 'de') { $lang = 'en' }
    [SBLang]::Lang = $lang
    if (-not $NoSave) { $State.misc['Lang'] = $lang; Save-State }
    $script:LangSync = $true
    try {
        $LangCode.Text = $lang.ToUpper()
        $LangDe.IsChecked = ($lang -eq 'de'); $LangEn.IsChecked = ($lang -eq 'en')
        $TourLangDe.IsChecked = ($lang -eq 'de'); $TourLangEn.IsChecked = ($lang -eq 'en')
    } finally { $script:LangSync = $false }
    [void][SBLang]::Apply($Window)
    if ($TourBubble.Visibility -eq 'Visible') { Show-TourStep $TourIdx -NoMove }
}

function Show-LangMenu {
    $menu = New-Object System.Windows.Controls.ContextMenu
    $menu.PlacementTarget = $BtnLang
    $menu.Placement = [System.Windows.Controls.Primitives.PlacementMode]::Bottom
    foreach ($l in @(@('de', 'Deutsch'), @('en', 'English'))) {
        $mi = New-Object System.Windows.Controls.MenuItem
        $mi.Header = "$($l[0].ToUpper())   $($l[1])"
        $mi.IsCheckable = $true
        $mi.IsChecked = ([SBLang]::Lang -eq $l[0])
        $mi.Tag = $l[0]
        $mi.Add_Click({ param($s, $e) try { Set-AppLang ([string]$s.Tag); Set-Status (L 'Applies instantly. No restart needed.') } catch { Write-Log "Language error: $_" } })
        [void]$menu.Items.Add($mi)
    }
    $menu.IsOpen = $true
}

# ---- tour
$script:TourIdx = 0
$script:TourPrevNav = 'NavHome'
$script:TourHoleGeo = $null
$script:TourSteps = @(
    @{ Title = 'Your PC score'; Text = 'This shows how optimized your PC is. The card below always names the one next step worth doing.'; Target = 'HomeHero'; Place = 'below'; Nav = $null },
    @{ Title = 'Quick Boost'; Text = 'The one button most people need. Pick Competitive - a restore point is made for you.'; Target = 'NavQuick'; Place = 'right'; Nav = 'NavQuick'; Reco = $true },
    @{ Title = 'Game Presets'; Text = 'Pick your game, then click Optimize.'; Target = 'NavGames'; Place = 'right'; Nav = 'NavGames'; Reco = $true },
    @{ Title = 'Live Monitor'; Text = 'Leave Silvan Boost open while you play (minimized is fine). Problems show up with a fix.'; Target = 'NavLive'; Place = 'right'; Nav = 'NavLive' },
    @{ Title = 'Network & Input'; Text = 'Ping Booster, Input Lag and game-safe Macros live here.'; Target = 'NetGroup'; Place = 'right'; Nav = 'NavPing' },
    @{ Title = 'Safety first'; Text = 'Everything can be undone. Backup & Restore has a Revert all button.'; Target = 'NavBackup'; Place = 'right'; Nav = 'NavBackup' }
)

function Start-Tour {
    $script:TourPrevNav = $ActiveNav
    $TourLayer.Visibility = 'Visible'
    $TourDone.Visibility = 'Collapsed'
    $TourBubble.Visibility = 'Collapsed'; $TourRing.Visibility = 'Collapsed'; $TourPulse.Visibility = 'Collapsed'
    $TourDim.Visibility = 'Collapsed'
    $TourWelcome.Visibility = 'Visible'
    $script:LangSync = $true
    $TourLangDe.IsChecked = ([SBLang]::Lang -eq 'de'); $TourLangEn.IsChecked = ([SBLang]::Lang -eq 'en')
    $script:LangSync = $false
    $TourWelcome.BeginAnimation([System.Windows.UIElement]::OpacityProperty, (New-Anim 1 220 0 0))
    Invoke-AnimateIn $TourWelcomeCard 14 320
    [void][SBLang]::Apply($TourLayer)
}

function Close-Tour([switch]$Finished) {
    $State.misc['TourDone'] = $true; Save-State
    $TourLayer.Visibility = 'Collapsed'
    $TourPulse.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $null)
    Select-NavFor $TourPrevNav
    $msg = $(if ($Finished) { 'Open the tour again any time with the ? button' } else { 'You can open the tour again any time with the ? button.' })
    Set-Status (L $msg)
    $p = New-Anim 1 500 0 0.3; $p.AutoReverse = $true; $p.RepeatBehavior = New-Object System.Windows.Media.Animation.RepeatBehavior(3)
    $BtnHelp.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $p)
}

function Begin-TourSteps {
    $TourWelcome.Visibility = 'Collapsed'
    $NavHome.IsChecked = $true
    $script:TourPrevNav = 'NavHome'
    $TourDim.Visibility = 'Visible'
    $full = New-Object System.Windows.Media.RectangleGeometry([System.Windows.Rect]::new(0, 0, 6000, 4000))
    $script:TourHoleGeo = New-Object System.Windows.Media.RectangleGeometry([System.Windows.Rect]::new(0, 0, 0, 0), 11, 11)
    $TourDim.Data = New-Object System.Windows.Media.CombinedGeometry([System.Windows.Media.GeometryCombineMode]::Exclude, $full, $TourHoleGeo)
    $TourDim.BeginAnimation([System.Windows.UIElement]::OpacityProperty, (New-Anim 1 220 0 0))
    $pulse = New-Anim 0 1600 0 0.8; $pulse.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
    $sc = New-Object System.Windows.Media.ScaleTransform 1, 1
    $TourPulse.RenderTransform = $sc
    $TourPulse.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $pulse)
    $sx = New-Anim 1.06 1600 0 1; $sx.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
    $sy = New-Anim 1.25 1600 0 1; $sy.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
    $sc.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, $sx)
    $sc.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, $sy)
    $script:TourIdx = -1
    Show-TourStep 0
}

function Get-TourRect([string]$target) {
    $els = @()
    switch ($target) {
        'NetGroup' { $els = @($CatNet, $SubNet) }
        default { $els = @((Get-Variable -Name $target -Scope Script -ValueOnly)) }
    }
    $r = [System.Windows.Rect]::Empty
    foreach ($el in $els) {
        if (-not $el -or $el.ActualWidth -le 0) { continue }
        $b = $el.TransformToAncestor($TourLayer).TransformBounds([System.Windows.Rect]::new(0, 0, $el.ActualWidth, $el.ActualHeight))
        $r.Union($b)
    }
    if ($r.IsEmpty) { return $null }
    $r.Inflate(4, 4)
    $r
}

function Set-CanvasAnim($el, $prop, [double]$to, [bool]$animate) {
    if ($animate -and -not [double]::IsNaN($el.GetValue($prop))) { $el.BeginAnimation($prop, (New-Anim $to 320)) }
    else { $el.BeginAnimation($prop, $null); $el.SetValue($prop, $to) }
}

function Show-TourStep([int]$i, [switch]$NoMove) {
    if ($i -lt 0) { return }
    if ($i -ge $TourSteps.Count) { Show-TourDone; return }
    $first = ($TourIdx -lt 0)
    $script:TourIdx = $i
    $st = $TourSteps[$i]
    # bubble content
    $TourStepTxt.Text = L "Step $($i + 1) of $($TourSteps.Count)"
    $TourTitle.Text = L $st.Title
    $TourText.Text = L $st.Text
    $TourReco.Visibility = $(if ($st.Reco) { 'Visible' } else { 'Collapsed' })
    $BtnTourBack.IsEnabled = ($i -gt 0)
    $BtnTourNext.Content = L $(if ($i -eq $TourSteps.Count - 1) { 'Finish' } else { 'Next' })
    $TourDots.Children.Clear()
    for ($k = 0; $k -lt $TourSteps.Count; $k++) {
        $d = New-Object System.Windows.Controls.Border
        $d.Height = 6; $d.CornerRadius = [System.Windows.CornerRadius]::new(3); $d.Margin = [System.Windows.Thickness]::new(0, 0, 6, 0)
        $d.Width = $(if ($k -eq $i) { 20 } else { 6 })
        $d.Background = Get-Brush $(if ($k -eq $i) { '#FF8A1F' } elseif ($k -lt $i) { '#73FF8A1F' } else { '#2A3858' })
        [void]$TourDots.Children.Add($d)
    }
    [void][SBLang]::Apply($TourBubble)
    if ($NoMove) { return }
    # open the matching sidebar category, then measure once the accordion animation is done
    if ($st.Nav) { Select-NavFor $st.Nav } else { Select-NavFor 'NavHome' }
    $t = New-Object System.Windows.Threading.DispatcherTimer
    $t.Interval = [TimeSpan]::FromMilliseconds($(if ($first) { 60 } else { 290 }))
    $t.Tag = @{ First = $first; Idx = $i }
    $t.Add_Tick({ param($s, $e) $s.Stop(); try { Move-TourSpot $s.Tag.Idx $s.Tag.First } catch { Write-Log "Tour error: $_" } })
    $t.Start()
}

function Move-TourSpot([int]$i, [bool]$first) {
    if ($i -ne $TourIdx -or $TourLayer.Visibility -ne 'Visible') { return }
    $st = $TourSteps[$i]
    $TourLayer.UpdateLayout()
    $r = Get-TourRect $st.Target
    if (-not $r) { $r = [System.Windows.Rect]::new(($TourLayer.ActualWidth / 2) - 1, 120, 2, 2) }
    $anim = -not $first
    # hole in the dim layer
    if ($anim) {
        $ra = New-Object System.Windows.Media.Animation.RectAnimation
        $ra.To = $r; $ra.Duration = [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds(320)); $ra.EasingFunction = $Ease
        $TourHoleGeo.BeginAnimation([System.Windows.Media.RectangleGeometry]::RectProperty, $ra)
    } else { $TourHoleGeo.Rect = $r }
    foreach ($ring in @($TourRing, $TourPulse)) {
        $ring.Visibility = 'Visible'
        Set-CanvasAnim $ring ([System.Windows.Controls.Canvas]::LeftProperty) $r.X $anim
        Set-CanvasAnim $ring ([System.Windows.Controls.Canvas]::TopProperty) $r.Y $anim
        Set-CanvasAnim $ring ([System.Windows.FrameworkElement]::WidthProperty) $r.Width $anim
        Set-CanvasAnim $ring ([System.Windows.FrameworkElement]::HeightProperty) $r.Height $anim
    }
    # bubble next to (or below) the highlighted spot
    $TourBubble.Visibility = 'Visible'
    $TourBubble.Measure([System.Windows.Size]::new(360, [double]::PositiveInfinity))
    $bh = [Math]::Max(150, $TourBubble.DesiredSize.Height)
    $W = $TourLayer.ActualWidth; $H = $TourLayer.ActualHeight
    if ($st.Place -eq 'below') {
        $bx = $r.X + 20; $by = $r.Bottom + 16
        if ($by + $bh -gt $H - 12) { $by = [Math]::Max(12, $r.Y - $bh - 16) }
    } else {
        $bx = $r.Right + 18; $by = $r.Y + $r.Height / 2 - 46
    }
    $bx = [Math]::Max(12, [Math]::Min($bx, $W - 372)); $by = [Math]::Max(12, [Math]::Min($by, $H - $bh - 12))
    Set-CanvasAnim $TourBubble ([System.Windows.Controls.Canvas]::LeftProperty) $bx $anim
    Set-CanvasAnim $TourBubble ([System.Windows.Controls.Canvas]::TopProperty) $by $anim
    if ($first) { Invoke-AnimateIn $TourBubble 6 260 }
}

function Show-TourDone {
    $TourBubble.Visibility = 'Collapsed'; $TourRing.Visibility = 'Collapsed'; $TourPulse.Visibility = 'Collapsed'
    $TourDim.Visibility = 'Collapsed'
    Select-NavFor 'NavHome'
    $TourDone.Visibility = 'Visible'
    $TourDone.BeginAnimation([System.Windows.UIElement]::OpacityProperty, (New-Anim 1 220 0 0))
    Invoke-AnimateIn $TourDoneCard 14 320
    $sc = New-Object System.Windows.Media.ScaleTransform 0.6, 0.6
    $TourCheck.RenderTransform = $sc
    $sc.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, (New-Anim 1 420 200 0.6))
    $sc.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, (New-Anim 1 420 200 0.6))
    $k = 0
    foreach ($c in $TourDoneList.Children) {
        $tt = New-Object System.Windows.Media.TranslateTransform
        $c.RenderTransform = $tt
        $c.BeginAnimation([System.Windows.UIElement]::OpacityProperty, (New-Anim 1 260 (480 + 60 * $k) 0))
        $tt.BeginAnimation([System.Windows.Media.TranslateTransform]::YProperty, (New-Anim 0 260 (480 + 60 * $k) 6))
        $k++
    }
    [void][SBLang]::Apply($TourDone)
}

function Register-TourEvents {
    $BtnHelp.Add_Click({ try { Start-Tour } catch { Write-Log "Tour error: $_" } })
    $BtnTourAgain.Add_Click({ try { Start-Tour } catch { Write-Log "Tour error: $_" } })
    $BtnLang.Add_Click({ try { Show-LangMenu } catch { Write-Log "Language error: $_" } })
    $LangDe.Add_Checked({ if (-not $LangSync) { Set-AppLang 'de' } })
    $LangEn.Add_Checked({ if (-not $LangSync) { Set-AppLang 'en' } })
    $TourLangDe.Add_Checked({ if (-not $LangSync) { Set-AppLang 'de' } })
    $TourLangEn.Add_Checked({ if (-not $LangSync) { Set-AppLang 'en' } })
    $BtnTourStart.Add_Click({ try { Begin-TourSteps } catch { Write-Log "Tour error: $_"; Close-Tour } })
    $BtnTourWelcomeSkip.Add_Click({ Close-Tour })
    $BtnTourSkip.Add_Click({ Close-Tour })
    $BtnTourBack.Add_Click({ try { Show-TourStep ($TourIdx - 1) } catch { } })
    $BtnTourNext.Add_Click({ try { Show-TourStep ($TourIdx + 1) } catch { Write-Log "Tour error: $_" } })
    $BtnTourDoneClose.Add_Click({ Close-Tour -Finished })
    $BtnTourOpenQuick.Add_Click({
            Close-Tour -Finished
            $NavQuick.IsChecked = $true
            try { $QbComp.IsChecked = $true } catch { } })
    $Window.Add_SizeChanged({ try { if ($TourBubble.Visibility -eq 'Visible') { Move-TourSpot $TourIdx $true } } catch { } })
    $Window.Add_PreviewKeyDown({ param($s, $e)
            if ($TourLayer.Visibility -ne 'Visible') { return }
            if ($e.Key -eq 'Escape') { $e.Handled = $true; Close-Tour }
            elseif ($TourBubble.Visibility -eq 'Visible' -and ($e.Key -eq 'Right' -or $e.Key -eq 'Return')) { $e.Handled = $true; Show-TourStep ($TourIdx + 1) }
            elseif ($TourBubble.Visibility -eq 'Visible' -and $e.Key -eq 'Left') { $e.Handled = $true; Show-TourStep ($TourIdx - 1) } })
}

# ------------------------------------------------------------------ 2.5: benchmark, game configs, tray, history, sharing, report
# ---- before / after benchmark
$script:BenchRun = $null
$script:BenchFocus = $false
$script:BenchSecs = 120

function Get-BenchData {
    $b = $State.misc['Bench']
    if (-not ($b -is [hashtable])) { $b = @{}; $State.misc['Bench'] = $b }
    $b
}

function Start-Bench([string]$phase) {
    if ($BenchRun) { return }
    $bd = Get-BenchData
    if ($phase -eq 'after' -and -not ($bd.Before -is [hashtable])) { Show-Msg (L 'Measure "before" first.') | Out-Null; return }
    if (-not $LiveAuto.IsChecked) { $LiveAuto.IsChecked = $true }
    $script:BenchRun = @{ Phase = $phase; Fps = New-Object System.Collections.ArrayList; Low = New-Object System.Collections.ArrayList; Lat = New-Object System.Collections.ArrayList; Game = $null; GameId = $null }
    $BenchLive.Visibility = 'Visible'; Invoke-AnimateIn $BenchLive 6 220
    $BenchProg.Maximum = $BenchSecs; $BenchProg.Value = 0
    $pulse = New-Anim 0.25 700 0 1; $pulse.AutoReverse = $true; $pulse.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
    $BenchDot.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $pulse)
    Update-BenchUI
    Write-Log "Benchmark ($phase) started."
}

function Stop-Bench([switch]$Cancel) {
    $r = $BenchRun; if (-not $r) { return }
    $script:BenchRun = $null
    $BenchDot.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $null)
    $BenchLive.Visibility = 'Collapsed'
    if ($Cancel -or $r.Fps.Count -lt 30) {
        Set-Status (L 'Benchmark cancelled - at least 30 seconds of gameplay are needed.')
        Update-BenchUI; return
    }
    $avg = { param($l) if ($l.Count -eq 0) { 0.0 } else { [double](($l | Measure-Object -Average).Average) } }
    $res = @{ Game = $r.Game; GameId = $r.GameId; Fps = (& $avg $r.Fps); Low = (& $avg $r.Low); Lat = (& $avg $r.Lat); Secs = $r.Fps.Count; Date = (Get-Date).ToString('yyyy-MM-dd HH:mm') }
    $bd = Get-BenchData
    if ($r.Phase -eq 'before') { $bd.Before = $res; $bd.Remove('After') } else { $bd.After = $res }
    Save-State
    Write-Log ("Benchmark {0}: {1} - {2:0} FPS avg, {3:0} 1% low, {4:0} ms latency ({5}s)" -f $r.Phase, $res.Game, $res.Fps, $res.Low, $res.Lat, $res.Secs)
    $msg = $(if ($r.Phase -eq 'before') { 'Before-measurement done. Now apply Quick Boost and restart your PC.' } else { 'Benchmark done - your result is ready.' })
    Set-Status (L $msg)
    Show-TrayTip 'Silvan Boost' (L $msg)
    $script:BenchFocus = $true
    Update-BenchUI
    if ($r.Phase -eq 'after') { Show-FromTray; $NavBench.IsChecked = $true }
}

function Update-Bench {
    $r = $BenchRun; if (-not $r) { return }
    $s = $LiveSession
    if ($s) {
        $bd = Get-BenchData
        if ($r.Phase -eq 'after' -and $bd.Before.GameId -and $s.Id -and $s.Id -ne $bd.Before.GameId) {
            $BenchLiveTxt.Text = (L 'Please play the same game as before:') + " $($bd.Before.Game)"
            return
        }
        if (-not $r.Game) { $r.Game = $s.Name; $r.GameId = $s.Id }
        $fps = [double]$Sync.Fps
        if ($fps -gt 0) {
            [void]$r.Fps.Add($fps)
            if ([double]$Sync.Low1 -gt 0) { [void]$r.Low.Add([double]$Sync.Low1) }
            if ([double]$Sync.InputLat -gt 0) { [void]$r.Lat.Add([double]$Sync.InputLat) }
        }
    }
    Update-BenchUI
    if ($r.Fps.Count -ge $BenchSecs) { Stop-Bench }
}

function Format-Delta([double]$before, [double]$after, [bool]$lowerBetter) {
    if ($before -le 0 -or $after -le 0) { return @{ Text = '-'; Good = $null } }
    $p = ($after - $before) / $before * 100
    $good = $(if ($lowerBetter) { $p -lt -1 } else { $p -gt 1 })
    $bad = $(if ($lowerBetter) { $p -gt 1 } else { $p -lt -1 })
    $sign = $(if ($p -ge 0) { '+' } else { '' })
    @{ Text = ('{0}{1:0}%' -f $sign, $p); Good = $(if ($good) { $true } elseif ($bad) { $false } else { $null }) }
}

function Update-BenchUI {
    if (-not $script:BenchS1) { return }
    $bd = Get-BenchData
    $b = $bd.Before; $a = $bd.After
    $r = $BenchRun
    # live card
    if ($r) {
        $n = $r.Fps.Count
        $BenchProg.Value = [Math]::Min($BenchSecs, $n)
        if (-not $LiveSession) {
            $BenchLiveTxt.Text = $(if ($n -gt 0) { (L 'Game closed - start it again to continue') + "  ($n / $BenchSecs s)" } else { L 'Start your game now - measuring begins as soon as it is detected.' })
        } elseif ($n -eq 0) { $BenchLiveTxt.Text = (L 'Waiting for frames from') + " $($LiveSession.Name)..." }
        else { $BenchLiveTxt.Text = (L 'Measuring') + " $($r.Game):  $n / $BenchSecs s" }
        $BenchLiveSub.Text = $(if ($n -gt 0 -and [double]$Sync.Fps -gt 0) { '{0:0} FPS' -f [double]$Sync.Fps } else { L 'Play normally - you can leave Silvan Boost minimized.' })
        $BtnBenchStop.Content = L $(if ($n -ge 30) { 'Finish now' } else { 'Cancel' })
    }
    # steps
    $BtnBench1.IsEnabled = -not $r; $BtnBench3.IsEnabled = (-not $r) -and ($b -is [hashtable])
    $BenchS1.Text = $(if ($b -is [hashtable]) { "$($b.Game): {0:0} FPS  -  $($b.Date)" -f [double]$b.Fps } else { '' })
    $BenchS3.Text = $(if ($a -is [hashtable]) { "$($a.Game): {0:0} FPS  -  $($a.Date)" -f [double]$a.Fps } elseif (-not ($b -is [hashtable])) { L 'Do step 1 first.' } else { '' })
    $BenchS2.Text = $(if ($b -is [hashtable] -and -not ($a -is [hashtable])) { L 'Restart the game after boosting, ideally the whole PC.' } else { '' })
    $done = @(($b -is [hashtable]), ($a -is [hashtable]), ($a -is [hashtable]))
    for ($i = 1; $i -le 3; $i++) {
        $nb = Get-Variable -Name "BenchNum$i" -Scope Script -ValueOnly; $nt = Get-Variable -Name "BenchNumTxt$i" -Scope Script -ValueOnly
        if ($done[$i - 1]) { $nb.Background = Get-Brush '#242ED47A'; $nb.BorderBrush = Get-Brush '#802ED47A'; $nt.Text = [string][char]0xE73E; $nt.FontFamily = $Window.FindResource('IconFont'); $nt.Foreground = Get-Brush '#2ED47A' }
        else { $nb.Background = Get-Brush '#24FF8A1F'; $nb.BorderBrush = Get-Brush '#59FF8A1F'; $nt.Text = "$i"; $nt.FontFamily = New-Object System.Windows.Media.FontFamily('Segoe UI'); $nt.Foreground = Get-Brush '#FFB36B' }
    }
    $BtnBench1.Content = L $(if ($b -is [hashtable]) { 'Measure again' } else { 'Start measuring' })
    $BtnBench3.Content = L $(if ($a -is [hashtable]) { 'Measure again' } else { 'Start measuring' })
    # result
    if (($b -is [hashtable]) -and ($a -is [hashtable])) {
        $BenchResult.Visibility = 'Visible'; $BenchActions.Visibility = 'Visible'
        $BenchGame.Text = [string]$a.Game
        $BenchDate.Text = [string]$a.Date
        $BenchTiles.Children.Clear()
        $tiles = @(@('AVERAGE FPS', [double]$b.Fps, [double]$a.Fps, $false, '{0:0}'), @('1% LOW FPS', [double]$b.Low, [double]$a.Low, $false, '{0:0}'), @('PC LATENCY', [double]$b.Lat, [double]$a.Lat, $true, '{0:0} ms'))
        $k = 0
        foreach ($t in $tiles) {
            $d = Format-Delta $t[1] $t[2] $t[3]
            $col = $(if ($d.Good -eq $true) { '#2ED47A' } elseif ($d.Good -eq $false) { '#F87171' } else { '#C3CBDD' })
            $bv = $(if ($t[1] -gt 0) { $t[4] -f $t[1] } else { 'n/a' }); $av = $(if ($t[2] -gt 0) { $t[4] -f $t[2] } else { 'n/a' })
            $x = @"
<Border $NS CornerRadius="12" Background="#0E1526" BorderBrush="#1E2A45" BorderThickness="1" Padding="16,14" Margin="$(if ($k -eq 0) { '0' } else { '5' }),0,$(if ($k -eq 2) { '0' } else { '5' }),0">
  <StackPanel>
    <TextBlock Text="$(X (L $t[0]))" FontSize="11" FontWeight="Bold" Foreground="#7F8BA6"/>
    <TextBlock Text="$(X $d.Text)" FontSize="34" FontWeight="SemiBold" Foreground="$col" Margin="0,4,0,0" FontFamily="Segoe UI Variable Display, Segoe UI"/>
    <TextBlock Text="$(X $bv)  &#x2192;  $(X $av)" FontSize="13" Foreground="#A9B3CC"/>
  </StackPanel>
</Border>
"@
            [void]$BenchTiles.Children.Add([System.Windows.Markup.XamlReader]::Parse($x)); $k++
        }
        $df = Format-Delta ([double]$b.Fps) ([double]$a.Fps) $false
        $dl = Format-Delta ([double]$b.Low) ([double]$a.Low) $false
        $BenchVerdict.Text = $(if ($df.Good -eq $true -or $dl.Good -eq $true) { L 'Your PC runs this game better after the boost. Smoother 1% lows matter most - they are what you feel as stutter.' }
            elseif ($df.Good -eq $false) { L 'The result is lower than before. Make sure you tested the same scene and settings - or check the Live Monitor for problems.' }
            else { L 'About the same as before - your PC was already well tuned. Check the PC Scanner for bigger wins like XMP or the monitor refresh rate.' })
        $BenchSpecs.Text = "$($HW.CpuName)  |  $($HW.GpuName)  |  Silvan Boost $AppVersion"
        [void][SBLang]::Apply($BenchResult)
    } else { $BenchResult.Visibility = 'Collapsed'; $BenchActions.Visibility = 'Collapsed' }
}

function Save-BenchImage {
    $el = $BenchResult
    $el.UpdateLayout()
    $w = [int][Math]::Ceiling($el.ActualWidth); $h = [int][Math]::Ceiling($el.ActualHeight)
    if ($w -le 0 -or $h -le 0) { return }
    $scale = 2.0
    $bmp = New-Object System.Windows.Media.Imaging.RenderTargetBitmap([int]($w * $scale), [int]($h * $scale), 96 * $scale, 96 * $scale, [System.Windows.Media.PixelFormats]::Pbgra32)
    $dv = New-Object System.Windows.Media.DrawingVisual
    $dc = $dv.RenderOpen()
    $dc.DrawRectangle((Get-Brush '#0A0F1C'), $null, [System.Windows.Rect]::new(0, 0, $w, $h))
    $vb = New-Object System.Windows.Media.VisualBrush($el)
    $dc.DrawRectangle($vb, $null, [System.Windows.Rect]::new(0, 0, $w, $h))
    $dc.Close()
    $bmp.Render($dv)
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Title = L 'Save as image'
    $dlg.Filter = 'PNG (*.png)|*.png'
    $dlg.FileName = 'SilvanBoost-Benchmark-' + (([string]$BenchGame.Text) -replace '[^A-Za-z0-9]+', '') + '.png'
    $dlg.InitialDirectory = [Environment]::GetFolderPath('MyPictures')
    if (-not $dlg.ShowDialog($Window)) { return }
    $enc = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bmp))
    $fs = [IO.File]::Create($dlg.FileName)
    try { $enc.Save($fs) } finally { $fs.Close() }
    Set-Status ((L 'Image saved:') + " $($dlg.FileName)")
    try { Start-Process 'explorer.exe' -ArgumentList "/select,`"$($dlg.FileName)`"" } catch { }
}

# ---- FPS history per game
function Add-GameHistory($s, [double]$fps, [double]$low, [double]$lat, [double]$mins) {
    if (-not $s.Id -or $fps -le 0 -or $mins -lt 1) { return }
    $h = $State.misc['History']
    if (-not ($h -is [hashtable])) { $h = @{}; $State.misc['History'] = $h }
    $g = $h[$s.Id]
    if (-not ($g -is [hashtable])) { $g = @{ Name = [string]$s.Name; S = @() }; $h[$s.Id] = $g }
    $g.Name = [string]$s.Name
    $g.S = @(@($g.S | Where-Object { $_ -is [hashtable] }) + , @{ D = (Get-Date).ToString('yyyy-MM-dd HH:mm'); F = [Math]::Round($fps, 1); L = [Math]::Round($low, 1); T = [Math]::Round($lat, 1); M = [Math]::Round($mins) })
    if ($g.S.Count -gt 60) { $g.S = @($g.S | Select-Object -Last 60) }
    $script:HistSel = $s.Id
    Save-State
}

$script:HistSel = $null
function Build-History {
    if (-not $script:HistChips) { return }
    $h = $State.misc['History']
    $HistChips.Children.Clear()
    if (-not ($h -is [hashtable]) -or $h.Count -eq 0) { $HistCanvas.Children.Clear(); return }
    if (-not $HistSel -or -not $h.ContainsKey($HistSel)) { $script:HistSel = @($h.Keys)[0] }
    foreach ($id in @($h.Keys | Sort-Object { $h[$_].Name })) {
        $rb = New-Object System.Windows.Controls.RadioButton
        $rb.Content = "$($h[$id].Name)  $(@($h[$id].S).Count)"; $rb.GroupName = 'hist'; $rb.Tag = $id
        $rb.Style = $Window.FindResource('Chip'); $rb.Margin = [System.Windows.Thickness]::new(0, 0, 8, 8)
        if ($id -eq $HistSel) { $rb.IsChecked = $true }
        $rb.Add_Checked({ param($sd, $e) $script:HistSel = [string]$sd.Tag; Draw-History })
        [void]$HistChips.Children.Add($rb)
    }
    Draw-History
}

function Draw-History {
    $HistCanvas.Children.Clear()
    $h = $State.misc['History']; if (-not ($h -is [hashtable]) -or -not $HistSel) { return }
    $pts = @(@($h[$HistSel].S) | Where-Object { $_ -is [hashtable] })
    if ($pts.Count -eq 0) { return }
    $W = $HistCanvas.ActualWidth; if ($W -lt 50) { $W = 760 }
    $H = 170.0; $padL = 40.0; $padB = 22.0; $padT = 8.0
    $max = 0.0; foreach ($p in $pts) { if ([double]$p.F -gt $max) { $max = [double]$p.F } }
    if ($max -le 0) { return }
    $top = [Math]::Ceiling($max / 50) * 50
    $sx = $(if ($pts.Count -gt 1) { ($W - $padL - 10) / ($pts.Count - 1) } else { 0 })
    foreach ($frac in 0, 0.5, 1) {
        $y = $padT + ($H - $padT - $padB) * (1 - $frac)
        $ln = New-Object System.Windows.Shapes.Line
        $ln.X1 = $padL; $ln.X2 = $W; $ln.Y1 = $y; $ln.Y2 = $y; $ln.Stroke = Get-Brush '#1A2440'; $ln.StrokeThickness = 1
        [void]$HistCanvas.Children.Add($ln)
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = '{0:0}' -f ($top * $frac); $tb.FontSize = 10.5; $tb.Foreground = Get-Brush '#5A6685'
        [System.Windows.Controls.Canvas]::SetLeft($tb, 0); [System.Windows.Controls.Canvas]::SetTop($tb, $y - 8)
        [void]$HistCanvas.Children.Add($tb)
    }
    foreach ($series in @(@('F', '#FF8A1F'), @('L', '#2ED47A'))) {
        $pl = New-Object System.Windows.Shapes.Polyline
        $pl.Stroke = Get-Brush $series[1]; $pl.StrokeThickness = 2.2; $pl.StrokeLineJoin = 'Round'
        $i = 0
        foreach ($p in $pts) {
            $v = [double]$p[$series[0]]
            $x = $padL + $(if ($pts.Count -gt 1) { $i * $sx } else { ($W - $padL) / 2 })
            $y = $padT + ($H - $padT - $padB) * (1 - [Math]::Min(1, $v / $top))
            if ($v -gt 0) {
                [void]$pl.Points.Add([System.Windows.Point]::new($x, $y))
                $dot = New-Object System.Windows.Shapes.Ellipse
                $dot.Width = 6; $dot.Height = 6; $dot.Fill = Get-Brush $series[1]
                $dot.ToolTip = "$($p.D)  -  {0:0} FPS avg, {1:0} 1% low, {2} min" -f [double]$p.F, [double]$p.L, $p.M
                [System.Windows.Controls.Canvas]::SetLeft($dot, $x - 3); [System.Windows.Controls.Canvas]::SetTop($dot, $y - 3)
                [void]$HistCanvas.Children.Add($dot)
            }
            $i++
        }
        [void]$HistCanvas.Children.Insert(0, $pl)
    }
    foreach ($edge in @(@(0, $padL), @(($pts.Count - 1), ($W - 70)))) {
        if ($pts.Count -lt 2 -and $edge[0] -ne 0) { continue }
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = ([string]$pts[$edge[0]].D).Substring(0, 10); $tb.FontSize = 10.5; $tb.Foreground = Get-Brush '#5A6685'
        [System.Windows.Controls.Canvas]::SetLeft($tb, $edge[1]); [System.Windows.Controls.Canvas]::SetTop($tb, $H - 16)
        [void]$HistCanvas.Children.Add($tb)
    }
    $last = $pts[-1]
    $avgAll = ($pts | ForEach-Object { [double]$_.F } | Measure-Object -Average).Average
    $diff = $(if ($avgAll -gt 0) { ([double]$last.F - $avgAll) / $avgAll * 100 } else { 0 })
    $HistInfo.Text = (L 'Sessions:') + " $($pts.Count)  -  " + (L 'last:') + (" {0:0} FPS ({1}{2:0}% " -f [double]$last.F, $(if ($diff -ge 0) { '+' } else { '' }), $diff) + (L 'vs. your average') + ')'
}

# ---- write pro settings into game config files
$script:GameCfgs = @{
    fortnite = @{ Name = 'Fortnite'; Format = 'ini'; Procs = @('FortniteClient-Win64-Shipping', 'FortniteLauncher')
        Set = [ordered]@{ 'bUseVSync' = 'False'; 'bMotionBlur' = 'False'; 'bShowFPS' = 'True'; 'FrameRateLimit' = '0.000000'
            'sg.ViewDistanceQuality' = '0'; 'sg.AntiAliasingQuality' = '0'; 'sg.ShadowQuality' = '0'; 'sg.GlobalIlluminationQuality' = '0'; 'sg.ReflectionQuality' = '0'
            'sg.PostProcessQuality' = '0'; 'sg.TextureQuality' = '0'; 'sg.EffectsQuality' = '0'; 'sg.FoliageQuality' = '0'; 'sg.ShadingQuality' = '0' } }
    cs2 = @{ Name = 'Counter-Strike 2'; Format = 'kv'; Procs = @('cs2')
        Set = [ordered]@{ 'setting.mat_vsync' = '0'; 'setting.r_low_latency' = '2'; 'setting.shaderquality' = '0'; 'setting.r_aoproxy_enable' = '0'; 'setting.r_csgo_fsr_upsample' = '0' } }
    apex = @{ Name = 'Apex Legends'; Format = 'kv'; Procs = @('r5apex', 'r5apex_dx12')
        Set = [ordered]@{ 'setting.mat_vsync_mode' = '0'; 'setting.dvs_enable' = '0'; 'setting.mat_antialias_mode' = '0'; 'setting.ssao_enabled' = '0'; 'setting.volumetric_lighting' = '0'
            'setting.cl_ragdoll_maxcount' = '0'; 'setting.r_createmodeldecals' = '0'; 'setting.mat_depthfeather_enable' = '0'; 'setting.particle_cpu_level' = '0'; 'setting.mat_forceaniso' = '2' } }
}

function Get-GameCfgFiles([string]$id) {
    $l = @()
    switch ($id) {
        'fortnite' { $l = @(Join-Path $env:LOCALAPPDATA 'FortniteGame\Saved\Config\WindowsClient\GameUserSettings.ini') }
        'apex' { $l = @(Join-Path $env:USERPROFILE 'Saved Games\Respawn\Apex\local\videoconfig.txt') }
        'cs2' {
            $root = Get-RegValue 'HKCU:\Software\Valve\Steam' 'SteamPath'
            if ($root) {
                $ud = Join-Path ($root -replace '/', '\') 'userdata'
                if (Test-Path -LiteralPath $ud) {
                    foreach ($u in @(Get-ChildItem -LiteralPath $ud -Directory -ErrorAction SilentlyContinue)) { $l += (Join-Path $u.FullName '730\local\cfg\cs2_video.txt') }
                }
            }
        }
    }
    @($l | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
}

function Get-GameCfgBackupDir([string]$id) { Join-Path $DataDir "gamecfg\$id" }

function Read-TextKeepEncoding([string]$path) {
    $bytes = [IO.File]::ReadAllBytes($path)
    $enc = New-Object System.Text.UTF8Encoding($false)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { $enc = [System.Text.Encoding]::Unicode }
    elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $enc = New-Object System.Text.UTF8Encoding($true) }
    $sr = New-Object IO.StreamReader($path, $enc, $true)
    try { $t = $sr.ReadToEnd() } finally { $sr.Close() }
    @{ Text = $t; Enc = $enc }
}

function Set-GameConfig([string]$id) {
    $c = $GameCfgs[$id]; if (-not $c) { return }
    $running = @(foreach ($pn in $c.Procs) { Get-Process -Name $pn -ErrorAction SilentlyContinue })
    if ($running.Count -gt 0) { Show-Msg ((L 'Please close the game first - it overwrites its settings when it exits.') + "`n`n$($c.Name)") 'Silvan Boost' 'OK' 'Warning' | Out-Null; return }
    $files = Get-GameCfgFiles $id
    if ($files.Count -eq 0) { Show-Msg (L 'The game settings file was not found. Start the game once, change any setting, close it - then try again.') | Out-Null; return }
    $r = Show-Msg ((L 'Write the pro settings into the game config now?') + "`n`n" + (L 'Your current settings are backed up and can be restored with Undo.')) 'Silvan Boost' 'YesNo' 'Question'
    if ([string]$r -ne 'Yes') { return }
    $bdir = Get-GameCfgBackupDir $id
    if (-not (Test-Path -LiteralPath (Join-Path $bdir 'map.json'))) {
        New-Item -ItemType Directory -Path $bdir -Force | Out-Null
        $map = @(); $i = 0
        foreach ($f in $files) { $b = Join-Path $bdir ("{0}_{1}" -f $i, (Split-Path -Leaf $f)); Copy-Item -LiteralPath $f -Destination $b -Force; $map += , @{ Src = $f; Bak = $b }; $i++ }
        ConvertTo-Json -InputObject @($map) -Depth 3 | Set-Content -LiteralPath (Join-Path $bdir 'map.json') -Encoding UTF8
    }
    $changed = 0; $found = 0
    foreach ($f in $files) {
        $d = Read-TextKeepEncoding $f; $t = $d.Text
        foreach ($k in $c.Set.Keys) {
            $v = $c.Set[$k]; $ek = [regex]::Escape($k)
            if ($c.Format -eq 'ini') { $rx = "(?m)^(\s*$ek=)([^\r\n]*)" } else { $rx = "(?m)^(\s*`"$ek`"\s+`")([^`"\r\n]*)(`")" }
            $m = [regex]::Match($t, $rx)
            if (-not $m.Success) { continue }
            $found++
            if ($m.Groups[2].Value -ne $v) {
                $t = [regex]::Replace($t, $rx, { param($mm) if ($mm.Groups.Count -gt 3 -and $mm.Groups[3].Success) { $mm.Groups[1].Value + $v + $mm.Groups[3].Value } else { $mm.Groups[1].Value + $v } })
                $changed++
            }
        }
        $fi = Get-Item -LiteralPath $f
        $ro = $fi.IsReadOnly
        if ($ro) { $fi.IsReadOnly = $false }
        [IO.File]::WriteAllText($f, $t, $d.Enc)
        if ($ro) { (Get-Item -LiteralPath $f).IsReadOnly = $true }
    }
    Write-Log "Game config for $($c.Name): $changed of $found settings changed in $($files.Count) file(s)."
    Set-Status ("$($c.Name): " + (L 'pro settings written to the game config.'))
    Show-Msg ("$($c.Name)`n`n" + ((L '{0} settings changed, {1} were already right.') -f $changed, ($found - $changed)) + "`n`n" + (L 'Resolution, display mode and Reflex can still be checked in the game menu.')) | Out-Null
    Show-ProSettings $id
}

function Undo-GameConfig([string]$id) {
    $c = $GameCfgs[$id]; $bdir = Get-GameCfgBackupDir $id
    $mp = Join-Path $bdir 'map.json'
    if (-not (Test-Path -LiteralPath $mp)) { return }
    $running = @(foreach ($pn in $c.Procs) { Get-Process -Name $pn -ErrorAction SilentlyContinue })
    if ($running.Count -gt 0) { Show-Msg ((L 'Please close the game first - it overwrites its settings when it exits.') + "`n`n$($c.Name)") 'Silvan Boost' 'OK' 'Warning' | Out-Null; return }
    foreach ($e in @(Get-Content -LiteralPath $mp -Raw | ConvertFrom-Json)) {
        $src = [string]$e.Src; $bak = [string]$e.Bak
        if ((Test-Path -LiteralPath $bak) -and $bak.StartsWith($bdir, [StringComparison]::OrdinalIgnoreCase)) {
            if (Test-Path -LiteralPath $src) { $fi = Get-Item -LiteralPath $src; if ($fi.IsReadOnly) { $fi.IsReadOnly = $false } }
            Copy-Item -LiteralPath $bak -Destination $src -Force
        }
    }
    Remove-Item -LiteralPath $bdir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Game config for $($c.Name) restored."
    Set-Status ("$($c.Name): " + (L 'your previous game settings are back.'))
    Show-ProSettings $id
}

function Update-ProCfgBar([string]$id) {
    if (-not $script:ProCfgBar) { return }
    if (-not $GameCfgs.ContainsKey($id)) { $ProCfgBar.Visibility = 'Collapsed'; return }
    $ProCfgBar.Visibility = 'Visible'
    $files = Get-GameCfgFiles $id
    $hasBak = Test-Path -LiteralPath (Join-Path (Get-GameCfgBackupDir $id) 'map.json')
    $BtnProCfgUndo.Visibility = $(if ($hasBak) { 'Visible' } else { 'Collapsed' })
    $BtnProCfgApply.IsEnabled = ($files.Count -gt 0)
    $ProCfgTxt.Text = L $(if ($files.Count -eq 0) { 'Settings file not found - start the game once, then come back.' } elseif ($hasBak) { 'Pro settings applied. Undo brings back your old settings.' } else { 'Your current game config is backed up first. Close the game before applying.' })
}

# ---- auto game mode
$script:AgmSaved = $null
$script:AgmBg = @('chrome', 'msedge', 'firefox', 'opera', 'opera_gx', 'brave', 'vivaldi', 'OneDrive', 'Teams', 'ms-teams', 'Dropbox', 'GoogleDriveFS', 'EpicWebHelper', 'steamwebhelper',
    'EADesktop', 'EABackgroundService', 'Battle.net', 'RiotClientServices', 'GalaxyClient', 'UbisoftConnect', 'upc', 'CCXProcess', 'Creative Cloud', 'AdobeIPCBroker', 'MicrosoftEdgeUpdate', 'GoogleUpdate', 'iCloudDrive', 'Widgets', 'PhoneExperienceHost')

function Enter-AutoGameMode($w) {
    if ($State.misc['AutoGameMode'] -eq $false -or $AgmSaved) { return }
    $script:AgmSaved = @{ Prios = @{}; Game = 0 }
    $n = 0
    foreach ($name in $AgmBg) {
        foreach ($p in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            try { if ($p.PriorityClass -eq [System.Diagnostics.ProcessPriorityClass]::Normal) { $p.PriorityClass = 'BelowNormal'; $AgmSaved.Prios[$p.Id] = 1; $n++ } } catch { }
        }
    }
    try {
        if ($Sync.GamePid) {
            $gp = Get-Process -Id ([int]$Sync.GamePid) -ErrorAction Stop
            if ($gp.PriorityClass -eq [System.Diagnostics.ProcessPriorityClass]::Normal) { $gp.PriorityClass = 'High'; $AgmSaved.Game = $gp.Id }
        }
    } catch { }
    try { Enter-GameNetMode -Force } catch { }
    Write-Log "Auto game mode ON for $($w.Name): $n background process(es) lowered$(if ($AgmSaved.Game) { ', game priority high' })."
    Show-TrayTip 'Silvan Boost' ((L 'Game mode on for') + " $($w.Name)")
}

function Exit-AutoGameMode {
    $s = $AgmSaved; if (-not $s) { return }
    foreach ($id in @($s.Prios.Keys)) {
        try { $p = Get-Process -Id ([int]$id) -ErrorAction Stop; if ($p.PriorityClass -eq [System.Diagnostics.ProcessPriorityClass]::BelowNormal) { $p.PriorityClass = 'Normal' } } catch { }
    }
    $script:AgmSaved = $null
    Write-Log 'Auto game mode OFF: background priorities restored.'
}

# ---- tray icon
$script:Tray = $null
$script:ReallyQuit = $false
function Initialize-Tray {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $ni = New-Object System.Windows.Forms.NotifyIcon
    $ico = $null
    try { $ico = Get-LogoIcon } catch { }
    if (-not $ico) { try { if ($LauncherPath -and (Test-Path -LiteralPath $LauncherPath)) { $ico = [System.Drawing.Icon]::ExtractAssociatedIcon($LauncherPath) } } catch { } }
    if (-not $ico) { $ico = [System.Drawing.SystemIcons]::Application }
    $ni.Icon = $ico
    $ni.Text = 'Silvan Boost'
    $menu = New-Object System.Windows.Forms.ContextMenuStrip
    $miOpen = $menu.Items.Add('Open Silvan Boost'); $script:TrayMiOpen = $miOpen; $miOpen.Font = New-Object System.Drawing.Font($miOpen.Font, [System.Drawing.FontStyle]::Bold)
    $miOpen.Add_Click({ Show-FromTray })
    $miBench = $menu.Items.Add('Benchmark'); $miBench.Add_Click({ Show-FromTray; $NavBench.IsChecked = $true })
    [void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    $miExit = $menu.Items.Add('Exit'); $script:TrayMiExit = $miExit; $miExit.Add_Click({ $script:ReallyQuit = $true; $Window.Close() })
    $menu.Add_Opening({ param($s, $e) try { $script:TrayMiOpen.Text = L 'Open Silvan Boost'; $script:TrayMiExit.Text = L 'Exit' } catch { } })
    $ni.ContextMenuStrip = $menu
    $ni.Add_MouseClick({ param($s, $e) if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) { Show-FromTray } })
    $ni.Visible = $true
    $script:Tray = $ni
}

function Show-TrayTip([string]$title, [string]$text) {
    if (-not $Tray) { return }
    try { $Tray.ShowBalloonTip(4000, $title, $text, [System.Windows.Forms.ToolTipIcon]::Info) } catch { }
}

function Show-FromTray {
    try {
        if (-not $Window.IsVisible) { $Window.Show() }
        if ($Window.WindowState -eq 'Minimized') { $Window.WindowState = 'Normal' }
        $Window.Activate() | Out-Null
        $Window.Topmost = $true; $Window.Topmost = $false
    } catch { }
}

# ---- share setup (export / import)
$script:ImportKinds = @('remap', 'combo', 'text', 'macro', 'media', 'sniper', 'disable')
$script:StepTypes = @('down', 'up', 'press', 'mdown', 'mup', 'click', 'delay', 'text')

function Export-Setup {
    $active = @($Tweaks | Where-Object { $_.Active -and -not $_.Action } | ForEach-Object { $_.Id })
    $o = @{ SilvanBoostSetup = 1; Version = $AppVersion; Created = (Get-Date).ToString('yyyy-MM-dd HH:mm'); Tweaks = $active; Lang = [SBLang]::Lang }
    if ($MacroCfg) { $o.Macro = @{ Profiles = @($MacroCfg.Profiles); Macros = @($MacroCfg.Macros) } }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Title = L 'Export my setup'
    $dlg.Filter = 'Silvan Boost setup (*.sbsetup)|*.sbsetup'
    $dlg.FileName = "SilvanBoost-Setup-$env:USERNAME.sbsetup"
    $dlg.InitialDirectory = [Environment]::GetFolderPath('Desktop')
    if (-not $dlg.ShowDialog($Window)) { return }
    ConvertTo-Json -InputObject $o -Depth 10 | Set-Content -LiteralPath $dlg.FileName -Encoding UTF8
    Write-Log "Setup exported: $($active.Count) optimizations."
    Set-Status ((L 'Setup saved:') + " $($dlg.FileName)")
    try { Start-Process 'explorer.exe' -ArgumentList "/select,`"$($dlg.FileName)`"" } catch { }
}

function ConvertTo-SafeBinding($b, $idMap) {
    if (-not ($b -is [hashtable])) { return $null }
    $k = [string]$b.Kind
    if ($ImportKinds -notcontains $k) { return $null }   # "open app or website" is never imported
    $o = @{ Kind = $k }
    switch ($k) {
        'remap' { $v = [int]$b.Vk; if ($v -lt 1 -or $v -gt 254) { return $null }; $o.Vk = $v }
        'combo' { $vs = @(@($b.Vks) | ForEach-Object { [int]$_ } | Where-Object { $_ -ge 1 -and $_ -le 254 } | Select-Object -First 5); if ($vs.Count -eq 0) { return $null }; $o.Vks = $vs }
        'text' { $t = [string]$b.Text; if (-not $t) { return $null }; if ($t.Length -gt 500) { $t = $t.Substring(0, 500) }; $o.Text = $t }
        'macro' { $nid = $idMap[[string]$b.MacroId]; if (-not $nid) { return $null }; $o.MacroId = $nid }
        'media' { $m = [string]$b.Media; if ($MediaNames.Keys -notcontains $m) { return $null }; $o.Media = $m }
        'sniper' { $o.Speed = [Math]::Max(1, [Math]::Min(20, [int]$b.Speed)) }
    }
    $o
}

function Import-Setup {
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Title = L 'Import a setup'
    $dlg.Filter = 'Silvan Boost setup (*.sbsetup)|*.sbsetup'
    if (-not $dlg.ShowDialog($Window)) { return }
    if ((Get-Item -LiteralPath $dlg.FileName).Length -gt 2MB) { Show-Msg (L 'This is not a valid Silvan Boost setup file.') | Out-Null; return }
    try { $h = ConvertTo-Hash (Get-Content -LiteralPath $dlg.FileName -Raw | ConvertFrom-Json) } catch { $h = $null }
    if (-not ($h -is [hashtable]) -or [int]$h.SilvanBoostSetup -ne 1) { Show-Msg (L 'This is not a valid Silvan Boost setup file.') | Out-Null; return }
    $want = @(@($h.Tweaks) | ForEach-Object { [string]$_ } | Where-Object { $TweakById.ContainsKey($_) } | Select-Object -Unique)
    $ok = @(); $skip = 0
    foreach ($id in $want) {
        $t = $TweakById[$id]
        if ($t.Active) { continue }
        if (-not (Test-Suitable $t) -or $t.Action -or $t.Risk -in 'Advanced', 'Permanent') { $skip++; continue }
        $ok += $t
    }
    $mc = $h.Macro; $nProf = 0; $nMac = 0
    if ($mc -is [hashtable]) { $nProf = @(@($mc.Profiles) | Where-Object { $_ -is [hashtable] }).Count; $nMac = @(@($mc.Macros) | Where-Object { $_ -is [hashtable] }).Count }
    $msg = (L 'Import this setup?') + "`n`n" + ((L '{0} optimizations to turn on') -f $ok.Count)
    if ($skip) { $msg += "`n" + ((L '{0} skipped (advanced or not suitable for this PC)') -f $skip) }
    $msg += "`n" + ((L '{0} macro profiles, {1} macros') -f $nProf, $nMac)
    $r = Show-Msg $msg 'Silvan Boost' 'YesNo' 'Question'
    if ([string]$r -ne 'Yes') { return }
    if ($ok.Count -gt 0) {
        if (-not (Ensure-RestorePoint)) { return }
        Show-Overlay 'Applying optimizations...'
        foreach ($t in $ok) { try { [void](Set-TweakState $t $true -Quiet) } catch { Write-Log "Import: $($t.Id) failed: $_" } }
        Hide-Overlay
    }
    if (($mc -is [hashtable]) -and $MacroCfg) {
        $idMap = @{}
        foreach ($m in @(@($mc.Macros) | Where-Object { $_ -is [hashtable] } | Select-Object -First 100)) {
            $steps = @()
            foreach ($s in @(@($m.Steps) | Where-Object { $_ -is [hashtable] } | Select-Object -First 1000)) {
                $ty = [string]$s.Type; if ($StepTypes -notcontains $ty) { continue }
                $x = @{ Type = $ty }
                if ($s.Vk) { $x.Vk = [Math]::Max(1, [Math]::Min(254, [int]$s.Vk)) }
                if ($s.Button) { $x.Button = [Math]::Max(1, [Math]::Min(5, [int]$s.Button)) }
                if ($ty -eq 'delay') { $x.Ms = [Math]::Max(0, [Math]::Min(60000, [int]$s.Ms)) }
                if ($ty -eq 'text') { $tx = [string]$s.Text; if ($tx.Length -gt 500) { $tx = $tx.Substring(0, 500) }; $x.Text = $tx }
                $steps += , $x
            }
            $nid = 'm' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            $idMap[[string]$m.Id] = $nid
            $nm = ([string]$m.Name).Trim(); if (-not $nm) { $nm = 'Macro' }; if ($nm.Length -gt 40) { $nm = $nm.Substring(0, 40) }
            $rep = [string]$m.Repeat; if (@('once', 'held', 'toggle') -notcontains $rep) { $rep = 'once' }
            $MacroCfg.Macros = @($MacroCfg.Macros) + , @{ Id = $nid; Name = $nm; Steps = $steps; Repeat = $rep }
        }
        foreach ($p in @(@($mc.Profiles) | Where-Object { $_ -is [hashtable] } | Select-Object -First 50)) {
            $exe = ([string]$p.Exe).ToLower()
            if ($exe -and $exe -notmatch '^[a-z0-9_.\- ]{1,64}$') { continue }
            $target = $(if (-not $exe) { Get-MacroProfile 'desktop' } else { @($MacroCfg.Profiles | Where-Object { $_.Exe -eq $exe })[0] })
            if (-not $target) {
                $nm = ([string]$p.Name).Trim(); if (-not $nm) { $nm = $exe }; if ($nm.Length -gt 32) { $nm = $nm.Substring(0, 32) }
                $target = @{ Id = 'p' + [guid]::NewGuid().ToString('N').Substring(0, 8); Name = $nm; Exe = $exe; Game = [bool]$p.Game -or [bool]($Sync.Watch -and $Sync.Watch.ContainsKey($exe)); Bind = @{} }
                $MacroCfg.Profiles = @($MacroCfg.Profiles) + , $target
            }
            if ($p.Bind -is [hashtable]) {
                foreach ($k in @($p.Bind.Keys)) {
                    if ($k -notmatch '^(MOUSE_MIDDLE|MOUSE_BACK|MOUSE_FORWARD|KEY:[A-Z+]*:\d{1,3})$') { continue }
                    $b = ConvertTo-SafeBinding $p.Bind[$k] $idMap
                    if (-not $b) { continue }
                    if ($target.Game -and $SimpleKinds -notcontains $b.Kind) { continue }
                    $target.Bind[$k] = $b
                }
            }
        }
        Save-Macros
        $script:MacroInit = $false
    }
    Save-State
    foreach ($t in $Tweaks) { Update-TweakUI $t }
    Update-Stats
    Write-Log "Setup imported: $($ok.Count) optimizations, $nProf macro profiles, $nMac macros."
    Show-Msg (L 'Setup imported.') | Out-Null
}

# ---- problem report
function New-ProblemReport {
    $l = New-Object System.Collections.ArrayList
    [void]$l.Add("Silvan Boost problem report - $((Get-Date).ToString('yyyy-MM-dd HH:mm'))")
    [void]$l.Add("Version: $AppVersion   Language: $([SBLang]::Lang)")
    try { $os = Get-CimInstance Win32_OperatingSystem; [void]$l.Add("Windows: $($os.Caption) $($os.Version) build $($os.BuildNumber)") } catch { }
    [void]$l.Add("CPU: $($HW.CpuName)")
    [void]$l.Add("GPU: $($HW.GpuName)   Driver: $($HW.GpuDriver)$(if ($HW.GpuDriverDate) { " ($($HW.GpuDriverDate.ToString('yyyy-MM-dd')))" })")
    try { [void]$l.Add(("RAM: {0:0} GB" -f ((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB))) } catch { }
    [void]$l.Add("Laptop: $($HW.IsLaptop)   Active optimizations: $(@($Tweaks | Where-Object { $_.Active }).Count)")
    [void]$l.Add('')
    [void]$l.Add('--- Activity log (last 150 lines) ---')
    try { foreach ($x in @(Get-Content -LiteralPath $LogFile -Tail 150 -ErrorAction Stop)) { [void]$l.Add($x) } } catch { foreach ($x in $LogLines) { [void]$l.Add($x) } }
    $txt = ($l -join "`r`n") -replace [regex]::Escape($env:USERNAME), '<user>'
    $path = Join-Path ([Environment]::GetFolderPath('Desktop')) 'SilvanBoost-Report.txt'
    Set-Content -LiteralPath $path -Value $txt -Encoding UTF8
    try { [System.Windows.Clipboard]::SetText($txt) } catch { }
    Write-Log 'Problem report created on the desktop.'
    try { Start-Process 'explorer.exe' -ArgumentList "/select,`"$path`"" } catch { }
    Show-Msg (L 'The report is on your desktop (SilvanBoost-Report.txt) and copied to the clipboard. Send it to Silvan and describe what went wrong.') | Out-Null
}

function Register-FeatureEvents {
    $NavBench.Add_Checked({ Show-Page 'Bench' })
    $BtnBench1.Add_Click({ try { Start-Bench 'before' } catch { Write-Log "Benchmark error: $_" } })
    $BtnBench3.Add_Click({ try { Start-Bench 'after' } catch { Write-Log "Benchmark error: $_" } })
    $BtnBench2.Add_Click({ $NavQuick.IsChecked = $true; try { $QbComp.IsChecked = $true } catch { } })
    $BtnBenchStop.Add_Click({ try { if ($BenchRun -and $BenchRun.Fps.Count -ge 30) { Stop-Bench } else { Stop-Bench -Cancel } } catch { } })
    $BtnBenchSave.Add_Click({ try { Save-BenchImage } catch { Write-Log "Image error: $_"; Show-Msg "$($_.Exception.Message)" | Out-Null } })
    $BtnBenchReset.Add_Click({ $bd = Get-BenchData; $bd.Remove('Before'); $bd.Remove('After'); Save-State; Update-BenchUI })
    $BtnProCfgApply.Add_Click({ try { Set-GameConfig $ProSel } catch { Write-Log "Game config error: $_"; Show-Msg "$($_.Exception.Message)" 'Silvan Boost' 'OK' 'Warning' | Out-Null } })
    $BtnProCfgUndo.Add_Click({ try { Undo-GameConfig $ProSel } catch { Write-Log "Game config error: $_" } })
    $AutoGameTg.IsChecked = ($State.misc['AutoGameMode'] -ne $false)
    $AutoGameTg.Add_Click({ $State.misc['AutoGameMode'] = [bool]$AutoGameTg.IsChecked; Save-State; if (-not $AutoGameTg.IsChecked) { Exit-AutoGameMode } })
    $TrayTg.IsChecked = ($State.misc['TrayOnClose'] -ne $false)
    $TrayTg.Add_Click({ $State.misc['TrayOnClose'] = [bool]$TrayTg.IsChecked; Save-State })
    $BtnExport.Add_Click({ try { Export-Setup } catch { Write-Log "Export error: $_"; Show-Msg "$($_.Exception.Message)" | Out-Null } })
    $BtnImport.Add_Click({ try { Import-Setup } catch { Hide-Overlay; Write-Log "Import error: $_"; Show-Msg "$($_.Exception.Message)" | Out-Null } })
    $BtnReport.Add_Click({ try { New-ProblemReport } catch { Write-Log "Report error: $_" } })
    $HistCanvas.Add_SizeChanged({ try { Draw-History } catch { } })
    $Window.Add_Closing({ param($s, $e)
            if ($script:ReallyQuit -or $script:Restarting) { return }
            if ($State.misc['TrayOnClose'] -eq $false -or -not $Tray) { return }
            $e.Cancel = $true
            $Window.Hide()
            if (-not $State.misc['TrayHintShown']) {
                $State.misc['TrayHintShown'] = $true; Save-State
                Show-TrayTip 'Silvan Boost' (L 'Still running next to the clock. Right-click the icon to exit.')
            } })
}

# ------------------------------------------------------------------ account + license
# Users sign in with an account that Silvan approves. The server signs a short license
# (ECDSA P-256) bound to this PC; the app checks it offline and refreshes it online.
$script:AuthApi  = 'https://silvan-boost.silvan3004.workers.dev'
$script:AuthPubX = '8erztdKEVnfRqNnBIM9K2AVIMc5_AlK0bVKtXokfFW0'
$script:AuthPubY = 'EnZlH3nlRiyspyAyEBbywOCX8UYEqiNCOfRP4Fyp6rY'
$script:AuthFile = Join-Path $env:LOCALAPPDATA 'SilvanBoost\account.dat'
$script:Auth = @{ user = ''; sid = ''; license = ''; maxNow = 0; temp = $false }
$script:AuthUnlocked = $false
$script:AuthWasWaiting = $false
$script:AuthCall = $null
$script:AuthCallTimer = $null
$script:AuthPollTimer = $null
$script:AuthPollMode = ''
$script:AuthLastOnline = [datetime]::MinValue
$script:AuthPanel = ''
$script:PcId = ''

$script:LicOk = $false
try {
    Add-Type -AssemblyName System.Security
    Add-Type -ReferencedAssemblies @([System.Security.Cryptography.ECDsa].Assembly.Location) -TypeDefinition @'
using System;
using System.Text;
using System.Security.Cryptography;
public static class SBLic {
    static byte[] U(string s) {
        s = s.Replace('-', '+').Replace('_', '/');
        while (s.Length % 4 != 0) s += "=";
        return Convert.FromBase64String(s);
    }
    public static bool Verify(string x, string y, string lic) {
        try {
            int i = lic.IndexOf('.');
            if (i < 1) return false;
            string body = lic.Substring(0, i);
            byte[] sig = Convert.FromBase64String(lic.Substring(i + 1));
            if (sig.Length != 64) return false;
            ECParameters p = new ECParameters();
            p.Curve = ECCurve.NamedCurves.nistP256;
            p.Q = new ECPoint { X = U(x), Y = U(y) };
            using (ECDsa ec = ECDsa.Create(p)) {
                return ec.VerifyData(Encoding.ASCII.GetBytes(body), sig, HashAlgorithmName.SHA256);
            }
        } catch { return false; }
    }
    public static string Body(string lic) {
        int i = lic.IndexOf('.');
        return Encoding.UTF8.GetString(Convert.FromBase64String(lic.Substring(0, i)));
    }
}
'@
    $script:LicOk = $true
} catch { }

function Get-NowMs { [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }

function Get-PcId {
    $src = ''
    try {
        $hk = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $k = $hk.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
        if ($k) { $src = [string]$k.GetValue('MachineGuid'); $k.Close() }
        $hk.Close()
    } catch { }
    if (-not $src) { $src = "$env:COMPUTERNAME|$env:PROCESSOR_IDENTIFIER" }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("SilvanBoost|$($src.ToLower())"))
    $hex = -join ($h[0..5] | ForEach-Object { $_.ToString('X2') })
    "SB-$($hex.Substring(0, 4))-$($hex.Substring(4, 4))-$($hex.Substring(8, 4))"
}

function Get-WinLabel {
    try {
        $k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $name = [string]$k.ProductName
        if ([int]$k.CurrentBuildNumber -ge 22000) { $name = $name -replace 'Windows 10', 'Windows 11' }
        return ("$name $($k.DisplayVersion)").Trim()
    } catch { 'Windows' }
}

# ---- local storage (encrypted for this Windows user with DPAPI)
$script:AuthEntropy = [System.Text.Encoding]::UTF8.GetBytes('SilvanBoost.Account.v1')
function Save-Auth {
    try {
        New-Item -ItemType Directory -Path (Split-Path $AuthFile) -Force | Out-Null
        $json = @{ user = $Auth.user; sid = $Auth.sid; license = $Auth.license; maxNow = [double]$Auth.maxNow; temp = [bool]$Auth.temp } | ConvertTo-Json -Compress
        $b = [System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($json), $AuthEntropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllBytes($AuthFile, $b)
    } catch { Write-Log "Account save error: $($_.Exception.Message)" }
}
function Load-Auth {
    if (-not (Test-Path -LiteralPath $AuthFile)) { return }
    try {
        $b = [System.Security.Cryptography.ProtectedData]::Unprotect([System.IO.File]::ReadAllBytes($AuthFile), $AuthEntropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $j = [System.Text.Encoding]::UTF8.GetString($b) | ConvertFrom-Json
        $script:Auth.user = [string]$j.user; $script:Auth.sid = [string]$j.sid; $script:Auth.license = [string]$j.license
        $script:Auth.maxNow = [double]$j.maxNow; $script:Auth.temp = [bool]$j.temp
    } catch { Write-Log "Account file could not be read - sign in again." }
}
function Clear-Auth([switch]$KeepUser) {
    $u = $Auth.user
    $script:Auth = @{ user = ''; sid = ''; license = ''; maxNow = 0; temp = $false }
    if ($KeepUser) { $script:Auth.user = $u }
    try { Remove-Item -LiteralPath $AuthFile -Force -ErrorAction SilentlyContinue } catch { }
}

# returns @{ plan; until; exp } when the stored license is valid for this user + PC right now
function Get-LicenseInfo {
    $lic = [string]$Auth.license
    if (-not $lic -or -not $LicOk) { return $null }
    if (-not [SBLic]::Verify($AuthPubX, $AuthPubY, $lic)) { return $null }
    try { $j = [SBLic]::Body($lic) | ConvertFrom-Json } catch { return $null }
    if ([string]$j.u -ne [string]$Auth.user -or [string]$j.pc -ne $PcId) { return $null }
    $now = Get-NowMs
    if ($Auth.maxNow -and $now -lt ([double]$Auth.maxNow - 86400000)) { return $null }   # clock was turned back
    if ($now -ge [double]$j.exp) { return $null }
    $plan = [string]$j.plan; if ($plan -ne 'month') { $plan = 'life' }
    @{ plan = $plan; until = [double]$j.until; exp = [double]$j.exp }
}

function Format-Day([double]$ms) {
    if ($ms -le 0) { return '' }
    [DateTimeOffset]::FromUnixTimeMilliseconds([long]$ms).LocalDateTime.ToString('dd.MM.yyyy')
}
function Get-DaysLeft([double]$until) { [math]::Max(0, [math]::Ceiling(($until - (Get-NowMs)) / 86400000)) }

# ---- server calls (background runspace, result handled on the UI thread)
function Invoke-AuthApi([string]$path, [hashtable]$body, [scriptblock]$done) {
    if ($script:AuthCall) { return $false }
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript({
            param($url, $json, $ua)
            try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
            $resp = $null
            try {
                $req = [Net.HttpWebRequest]::Create($url)
                $req.Method = 'POST'; $req.ContentType = 'application/json'; $req.UserAgent = $ua
                $req.Timeout = 12000; $req.ReadWriteTimeout = 12000
                $bytes = [Text.Encoding]::UTF8.GetBytes($json); $req.ContentLength = $bytes.Length
                $st = $req.GetRequestStream(); $st.Write($bytes, 0, $bytes.Length); $st.Close()
                $resp = $req.GetResponse()
            } catch {
                $ex = $_.Exception
                while ($ex -and -not ($ex -is [Net.WebException])) { $ex = $ex.InnerException }
                if ($ex -and $ex.Response) { $resp = $ex.Response } else { return @{ code = 0; text = '' } }
            }
            try {
                $code = [int]$resp.StatusCode
                $rd = New-Object IO.StreamReader($resp.GetResponseStream(), [Text.Encoding]::UTF8)
                $t = $rd.ReadToEnd(); $rd.Close(); $resp.Close()
                return @{ code = $code; text = $t }
            } catch { return @{ code = 0; text = '' } }
        }).AddArgument("$AuthApi$path").AddArgument(($body | ConvertTo-Json -Compress)).AddArgument("SilvanBoost/$AppVersion")
    $script:AuthCall = @{ PS = $ps; H = $ps.BeginInvoke(); Done = $done }
    if (-not $script:AuthCallTimer) {
        $script:AuthCallTimer = New-Object System.Windows.Threading.DispatcherTimer
        $AuthCallTimer.Interval = [TimeSpan]::FromMilliseconds(150)
        $AuthCallTimer.Add_Tick({ Complete-AuthCall })
    }
    $AuthCallTimer.Start()
    $true
}

function Complete-AuthCall {
    $c = $script:AuthCall
    if (-not $c -or -not $c.H.IsCompleted) { return }
    $AuthCallTimer.Stop()
    $script:AuthCall = $null
    $r = @{ code = 0; data = $null }
    try {
        $o = @($c.PS.EndInvoke($c.H)) | Select-Object -Last 1
        if ($o) { $r.code = [int]$o.code; if ($o.text) { try { $r.data = $o.text | ConvertFrom-Json } catch { } } }
    } catch { }
    try { $c.PS.Dispose() } catch { }
    if ($r.code -gt 0) { $script:AuthLastOnline = Get-Date }
    try { & $c.Done $r } catch { Write-Log "Account error: $($_.Exception.Message)" }
}

function Get-AuthErrorText($r) {
    $e = ''; if ($r.data) { $e = [string]$r.data.error }
    switch ($e) {
        'wrong_login' { return 'Wrong username or password.' }
        'wrong_pc' { return 'This account belongs to a different PC. It only works on the PC where it was created - ask Silvan to reset it.' }
        'taken' { return 'This username is already taken. Try another one.' }
        'bad_user' { return 'Username: 3 to 20 characters, only letters, numbers and _ . -' }
        'bad_pass' { return 'Your password needs at least 6 characters.' }
        'too_many' { return 'Too many tries. Wait a few minutes and try again.' }
    }
    if ($r.code -eq 0) { return "Can't reach the Silvan Boost server. Check your internet connection and try again." }
    "Something went wrong on the server (error $($r.code)). Try again in a moment."
}

# ---- screens
function Set-AuthText($el, [string]$t) { $el.Text = [SBLang]::Tr($t) }

function Show-AuthPanel([string]$name) {
    foreach ($p in 'Busy', 'Login', 'Reg', 'Wait', 'Ok', 'Exp', 'Lock') {
        (Get-Variable -Name "Auth$($p)Panel" -ValueOnly).Visibility = $(if ($p -eq $name) { 'Visible' } else { 'Collapsed' })
    }
    $script:AuthPanel = $name
    $AuthLayer.Visibility = 'Visible'
    $AuthToast.Visibility = 'Collapsed'
    if ($script:AuthUnlocked) { $script:AuthUnlocked = $false; Update-AuthCard }
    # soft slide + fade of the card
    $dur = New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds(260))
    $ease = New-Object System.Windows.Media.Animation.CubicEase; $ease.EasingMode = 'EaseOut'
    $fade = New-Object System.Windows.Media.Animation.DoubleAnimation(0, 1, $dur); $fade.EasingFunction = $ease
    $move = New-Object System.Windows.Media.Animation.DoubleAnimation(14, 0, $dur); $move.EasingFunction = $ease
    $AuthCard.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fade)
    $AuthCard.RenderTransform.BeginAnimation([System.Windows.Media.TranslateTransform]::YProperty, $move)
    if ($name -eq 'Wait') {
        $spin = New-Object System.Windows.Media.Animation.DoubleAnimation(0, 360, (New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds(1100))))
        $spin.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
        $AuthSpin.RenderTransform.BeginAnimation([System.Windows.Media.RotateTransform]::AngleProperty, $spin)
    } else { $AuthSpin.RenderTransform.BeginAnimation([System.Windows.Media.RotateTransform]::AngleProperty, $null) }
    if ($name -eq 'Ok') {
        $pop = New-Object System.Windows.Media.Animation.DoubleAnimation(0.4, 1, (New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds(420))))
        $be = New-Object System.Windows.Media.Animation.BackEase; $be.Amplitude = 0.45; $be.EasingMode = 'EaseOut'; $pop.EasingFunction = $be
        $AuthOkCheck.RenderTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, $pop)
        $AuthOkCheck.RenderTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, $pop)
    }
    if ([SBLang]::Lang -eq 'de') { try { [void][SBLang]::Apply($AuthLayer) } catch { } }
    switch ($name) {
        'Login' { if ($AuthLUser.Text) { [void]$AuthLPass.Focus() } else { [void]$AuthLUser.Focus() } }
        'Reg' { [void]$AuthRUser.Focus() }
    }
}

function Show-AuthBusy([string]$title, [string]$err) {
    Set-AuthText $AuthBusyTitle $title
    $AuthBusyBar.Visibility = $(if ($err) { 'Collapsed' } else { 'Visible' })
    $AuthBusyErr.Visibility = $(if ($err) { 'Visible' } else { 'Collapsed' })
    $BtnAuthRetry.Visibility = $AuthBusyErr.Visibility
    $BtnAuthBusyOut.Visibility = $AuthBusyErr.Visibility
    if ($err) { Set-AuthText $AuthBusyErrTxt $err }
    Show-AuthPanel 'Busy'
}

function Show-AuthLogin([string]$sub, [string]$err) {
    if (-not $sub) { $sub = 'Sign in to use Silvan Boost.' }
    Set-AuthText $AuthLoginSub $sub
    $AuthLUser.Text = [string]$Auth.user
    $AuthLPass.Password = ''
    Set-AuthErr $AuthLErr $AuthLErrTxt $err
    Show-AuthPanel 'Login'
}

function Set-AuthErr($box, $txt, [string]$err) {
    if ($err) { Set-AuthText $txt $err; $box.Visibility = 'Visible' } else { $box.Visibility = 'Collapsed' }
}

function Show-AuthLocked([string]$kind) {
    $AuthLockErr.Visibility = 'Collapsed'
    switch ($kind) {
        'wrong_pc' {
            Set-AuthText $AuthLockTitle 'Wrong PC'
            Set-AuthText $AuthLockSub 'This account was created on a different PC.'
            Set-AuthText $AuthLockErrTxt 'Your account only works on the PC where you created it. New PC? Ask Silvan to reset your account, then sign in here again.'
            $AuthLockErr.Visibility = 'Visible'
        }
        'rejected' {
            Set-AuthText $AuthLockTitle 'Request declined'
            Set-AuthText $AuthLockSub 'Silvan did not approve this account. If you think this is a mistake, message him.'
        }
        default {
            Set-AuthText $AuthLockTitle 'This account is locked'
            Set-AuthText $AuthLockSub 'Silvan has ended access for this account. If you think this is a mistake, message him.'
        }
    }
    Show-AuthPanel 'Lock'
}

function Show-AuthOk($d) {
    $plan = [string]$d.plan
    Set-AuthText $AuthOkSub "Have fun with Silvan Boost, $($Auth.user)."
    if ($plan -eq 'month') {
        Set-AuthText $AuthOkPlan '1 month'
        Set-AuthText $AuthOkPillTxt "until $(Format-Day ([double]$d.until))"
        $AuthOkPill.Background = Get-Brush '#212ED47A'; $AuthOkPillTxt.Foreground = Get-Brush '#5BE39A'
    } else {
        Set-AuthText $AuthOkPlan 'Lifetime'
        Set-AuthText $AuthOkPillTxt 'never ends'
        $AuthOkPill.Background = Get-Brush '#24FF8A1F'; $AuthOkPillTxt.Foreground = Get-Brush '#FFB36B'
    }
    Show-AuthPanel 'Ok'
}

function Show-AuthExpired($d) {
    $day = Format-Day ([double]$d.until)
    if ($day) { Set-AuthText $AuthExpSub "Your month of Silvan Boost ended on $day. Message Silvan so he can extend it. The app opens again by itself." }
    else { Set-AuthText $AuthExpSub 'Message Silvan so he can extend it. The app opens again by itself.' }
    Show-AuthPanel 'Exp'
}

# account line in the user card (bottom left)
function Update-AuthCard {
    try {
        if (-not $Auth.user -or -not $script:AuthUnlocked) { $UserPlan.Visibility = 'Collapsed'; return }
        $dot = [string][char]0x00B7
        $info = Get-LicenseInfo
        if ($info -and $info.plan -eq 'month') {
            $n = Get-DaysLeft $info.until
            $left = $(if ($n -eq 1) { '1 day left' } else { "$n days left" })
            $UserPlan.Text = [SBLang]::Tr("Account $($Auth.user) $dot $left")
            $UserPlan.Foreground = Get-Brush $(if ($n -le 3) { '#FBBF24' } else { '#5BE39A' })
        } else {
            $UserPlan.Text = [SBLang]::Tr("Account $($Auth.user) $dot Lifetime")
            $UserPlan.Foreground = Get-Brush '#FFB36B'
        }
        $UserPlan.Visibility = 'Visible'
    } catch { }
}

function Show-AuthToastIfNeeded {
    $info = Get-LicenseInfo
    if (-not $info -or $info.plan -ne 'month') { $AuthToast.Visibility = 'Collapsed'; return }
    $n = Get-DaysLeft $info.until
    if ($n -gt 3) { $AuthToast.Visibility = 'Collapsed'; return }
    $today = (Get-Date).ToString('yyyy-MM-dd')
    if ($State.misc['AuthWarnDay'] -eq $today) { return }
    $State.misc['AuthWarnDay'] = $today; Save-State
    $msg = switch ($n) { 0 { 'Your plan ends today. Message Silvan if you want to extend it.' } 1 { 'Your plan ends in 1 day. Message Silvan if you want to extend it.' } default { "Your plan ends in $n days. Message Silvan if you want to extend it." } }
    Set-AuthText $AuthToastTxt $msg
    $AuthToast.Visibility = 'Visible'
    $AuthToast.BeginAnimation([System.Windows.UIElement]::OpacityProperty, (New-Object System.Windows.Media.Animation.DoubleAnimation(0, 1, (New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds(400))))))
    Show-TrayTip 'Silvan Boost' ([SBLang]::Tr($msg))
}

# ---- polling while waiting / expired, and the periodic check while unlocked
function Set-AuthPoll([string]$mode) {
    $script:AuthPollMode = $mode
    if (-not $script:AuthPollTimer) {
        $script:AuthPollTimer = New-Object System.Windows.Threading.DispatcherTimer
        $AuthPollTimer.Add_Tick({ try { Invoke-AuthPollTick } catch { Write-Log "Account check error: $_" } })
    }
    $AuthPollTimer.Stop()
    if (-not $mode) { return }
    $sec = switch ($mode) { 'wait' { 6 } 'exp' { 20 } default { 60 } }
    $AuthPollTimer.Interval = [TimeSpan]::FromSeconds($sec)
    $AuthPollTimer.Start()
}

function Invoke-AuthPollTick {
    if ($script:AuthCall -or -not $Auth.sid) { return }
    if ($AuthPollMode -eq 'run') {
        Update-AuthCard
        $info = Get-LicenseInfo
        # online re-check every 6 hours, or right away once the offline license has run out
        if ($info -and ((Get-Date) - $AuthLastOnline).TotalHours -lt 6) { return }
        if (-not $info -and ((Get-Date) - $AuthLastOnline).TotalSeconds -lt 50 -and $AuthLastOnline -ne [datetime]::MinValue) { return }
        Request-AuthStatus 'bg'
        return
    }
    Request-AuthStatus 'poll'
}

$script:AuthReqMode = ''
function Request-AuthStatus([string]$mode) {
    if ($script:AuthCall) { return }
    $script:AuthReqMode = $mode
    [void](Invoke-AuthApi '/api/status' @{ user = $Auth.user; sid = $Auth.sid; pcid = $PcId } { param($r) Receive-AuthStatus $r $script:AuthReqMode })
}

# one place that decides what to show for a server reply
function Receive-AuthStatus($r, [string]$mode) {
    $d = $r.data
    if ($r.code -eq 0 -or $r.code -eq 429 -or $r.code -ge 500 -or -not $d) {
        if ($mode -eq 'bg' -or $mode -eq 'poll') {
            # offline: keep going while the stored license is still valid
            if ($script:AuthUnlocked -and -not (Get-LicenseInfo)) { Show-AuthBusy 'Checking your account...' (Get-AuthErrorText $r); Set-AuthPoll '' }
            return
        }
        Show-AuthBusy 'Checking your account...' (Get-AuthErrorText $r)
        return
    }
    $err = [string]$d.error
    if ($err -eq 'signed_out') { Set-AuthPoll ''; Clear-Auth -KeepUser; Show-AuthLogin 'You were signed out. Please sign in again.'; return }
    if ($err -eq 'wrong_pc') { Set-AuthPoll ''; Show-AuthLocked 'wrong_pc'; return }
    if ($err) { if ($mode -eq 'initial') { Show-AuthBusy 'Checking your account...' (Get-AuthErrorText $r) }; return }
    Receive-AuthState $d $mode
}

function Receive-AuthState($d, [string]$mode) {
    switch ([string]$d.status) {
        'approved' {
            $script:Auth.license = [string]$d.license
            $script:Auth.maxNow = [math]::Max([double]$Auth.maxNow, (Get-NowMs))
            Save-Auth
            if ($script:AuthUnlocked) { Update-AuthCard; Show-AuthToastIfNeeded; return }
            if ($AuthWasWaiting -or $mode -eq 'login' -or $AuthPanel -eq 'Exp') { $script:AuthWasWaiting = $false; Set-AuthPoll ''; Show-AuthOk $d; return }
            Unlock-App
        }
        'pending' {
            $script:AuthWasWaiting = $true
            Set-AuthText $AuthWaitTitle "Almost there, $($Auth.user)"
            if ($AuthPanel -ne 'Wait') { Show-AuthPanel 'Wait' }
            Set-AuthPoll 'wait'
        }
        'expired' {
            $script:Auth.license = ''; Save-Auth
            if ($AuthPanel -ne 'Exp') { Show-AuthExpired $d }
            Set-AuthPoll 'exp'
        }
        'blocked' { Set-AuthPoll ''; $script:Auth.license = ''; Save-Auth; Show-AuthLocked 'blocked' }
        'rejected' { Set-AuthPoll ''; $script:Auth.license = ''; Save-Auth; Show-AuthLocked 'rejected' }
        default { if ($mode -eq 'initial') { Show-AuthBusy 'Checking your account...' (Get-AuthErrorText @{ code = 500; data = $null }) } }
    }
}

function Unlock-App {
    $script:AuthUnlocked = $true
    $AuthSpin.RenderTransform.BeginAnimation([System.Windows.Media.RotateTransform]::AngleProperty, $null)
    $fade = New-Object System.Windows.Media.Animation.DoubleAnimation(1, 0, (New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds(220))))
    $fade.Add_Completed({ $AuthLayer.Visibility = 'Collapsed'; $AuthLayer.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $null); $AuthLayer.Opacity = 1 })
    $AuthLayer.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fade)
    $script:AuthPanel = ''
    Update-AuthCard
    Set-AuthPoll 'run'
    if (-not $script:Started) {
        # let the fade play, then run the normal start (scan, tour ...)
        $t = New-Object System.Windows.Threading.DispatcherTimer
        $t.Interval = [TimeSpan]::FromMilliseconds(240)
        $t.Add_Tick({ param($s, $e) $s.Stop(); Start-Main; Update-AuthCard; Show-AuthToastIfNeeded })
        $t.Start()
    } else { Show-AuthToastIfNeeded }
}

function Invoke-AuthSignOut {
    Set-AuthPoll ''
    $script:AuthWasWaiting = $false
    Clear-Auth -KeepUser
    Show-AuthLogin
}

# ---- entry: decide before the main app starts
function Start-AuthGate {
    $script:PcId = Get-PcId
    $AuthPcId.Text = $PcId
    Load-Auth
    if ($Auth.temp) { Clear-Auth -KeepUser }   # 'Stay signed in' was off last time
    if ($Auth.sid -and (Get-LicenseInfo)) {
        Unlock-App
        Request-AuthStatus 'bg'
        return
    }
    if ($Auth.sid) { Show-AuthBusy 'Checking your account...' ''; Request-AuthStatus 'initial'; return }
    Show-AuthLogin
}

function Invoke-AuthLogin {
    $u = $AuthLUser.Text.Trim(); $p = $AuthLPass.Password
    if (-not $u -or -not $p) { Set-AuthErr $AuthLErr $AuthLErrTxt 'Enter your username and password.'; return }
    Set-AuthErr $AuthLErr $AuthLErrTxt ''
    $BtnAuthLogin.IsEnabled = $false; $BtnAuthLogin.Content = [SBLang]::Tr('Signing in...')
    $ok = Invoke-AuthApi '/api/login' @{ user = $u; pass = $p; pcid = $PcId } {
        param($r)
        $BtnAuthLogin.IsEnabled = $true; $BtnAuthLogin.Content = [SBLang]::Tr('Sign in')
        if ($r.code -eq 200 -and $r.data -and $r.data.sid) {
            $script:Auth.user = [string]$r.data.user; $script:Auth.sid = [string]$r.data.sid
            $script:Auth.temp = -not [bool]$AuthRemember.IsChecked
            Save-Auth
            $AuthLPass.Password = ''
            Receive-AuthState $r.data 'login'
            return
        }
        Set-AuthErr $AuthLErr $AuthLErrTxt (Get-AuthErrorText $r)
    }
    if (-not $ok) { $BtnAuthLogin.IsEnabled = $true; $BtnAuthLogin.Content = [SBLang]::Tr('Sign in') }
}

function Invoke-AuthRegister {
    $u = $AuthRUser.Text.Trim(); $p = $AuthRPass.Password; $p2 = $AuthRPass2.Password
    $msg = ''
    if ($u -notmatch '^[A-Za-z0-9_.-]{3,20}$') { $msg = 'Username: 3 to 20 characters, only letters, numbers and _ . -' }
    elseif ($p.Length -lt 6) { $msg = 'Your password needs at least 6 characters.' }
    elseif ($p -cne $p2) { $msg = 'The two passwords are not the same.' }
    if ($msg) { Set-AuthErr $AuthRErr $AuthRErrTxt $msg; return }
    Set-AuthErr $AuthRErr $AuthRErrTxt ''
    $BtnAuthReg.IsEnabled = $false; $BtnAuthReg.Content = [SBLang]::Tr('Creating account...')
    $ok = Invoke-AuthApi '/api/register' @{ user = $u; pass = $p; pcid = $PcId; win = (Get-WinLabel); ver = $AppVersion } {
        param($r)
        $BtnAuthReg.IsEnabled = $true; $BtnAuthReg.Content = [SBLang]::Tr('Create account')
        if ($r.code -eq 200 -and $r.data -and $r.data.sid) {
            $script:Auth.user = $AuthRUser.Text.Trim(); $script:Auth.sid = [string]$r.data.sid; $script:Auth.temp = $false
            Save-Auth
            $AuthRPass.Password = ''; $AuthRPass2.Password = ''
            Write-Log "Account $($Auth.user) created - waiting for approval."
            Receive-AuthState $r.data 'login'
            return
        }
        Set-AuthErr $AuthRErr $AuthRErrTxt (Get-AuthErrorText $r)
    }
    if (-not $ok) { $BtnAuthReg.IsEnabled = $true; $BtnAuthReg.Content = [SBLang]::Tr('Create account') }
}

function Show-AccountMenu {
    $menu = New-Object System.Windows.Controls.ContextMenu
    $menu.PlacementTarget = $UserCardBox
    $menu.Placement = [System.Windows.Controls.Primitives.PlacementMode]::Top
    $hd = New-Object System.Windows.Controls.MenuItem
    $hd.Header = $(if ($Auth.user) { [SBLang]::Tr("Signed in as $($Auth.user)") } else { [SBLang]::Tr('Not signed in') })
    $hd.IsEnabled = $false
    [void]$menu.Items.Add($hd)
    $mi = New-Object System.Windows.Controls.MenuItem
    $mi.Header = [SBLang]::Tr('Sign out')
    $mi.Add_Click({ Invoke-AuthSignOut })
    [void]$menu.Items.Add($mi)
    $menu.IsOpen = $true
}

function Initialize-AuthEvents {
    try {
        $img = Get-LogoImage 128
        foreach ($n in 'AuthLogo0', 'AuthLogo1', 'AuthLogo2') { (Get-Variable -Name $n -ValueOnly).Source = $img }
        $AuthLogoSmall.Source = Get-LogoImage 36
    } catch { }
    $BtnAuthLogin.Add_Click({ try { Invoke-AuthLogin } catch { Write-Log "Login error: $_" } })
    $BtnAuthReg.Add_Click({ try { Invoke-AuthRegister } catch { Write-Log "Register error: $_" } })
    $AuthLPass.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { Invoke-AuthLogin } })
    $AuthLUser.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { [void]$AuthLPass.Focus() } })
    $AuthRPass2.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { Invoke-AuthRegister } })
    $BtnAuthToReg.Add_Click({ Set-AuthErr $AuthRErr $AuthRErrTxt ''; $AuthRUser.Text = ''; Show-AuthPanel 'Reg' })
    $BtnAuthToLogin.Add_Click({ Show-AuthLogin })
    $BtnAuthGo.Add_Click({ Unlock-App })
    $BtnAuthWaitOut.Add_Click({ Invoke-AuthSignOut })
    $BtnAuthExpOut.Add_Click({ Invoke-AuthSignOut })
    $BtnAuthLockOut.Add_Click({ Invoke-AuthSignOut })
    $BtnAuthBusyOut.Add_Click({ Invoke-AuthSignOut })
    $BtnAuthRetry.Add_Click({ Show-AuthBusy 'Checking your account...' ''; Request-AuthStatus 'initial' })
    $BtnAuthToastX.Add_Click({ $AuthToast.Visibility = 'Collapsed' })
    $BtnAuthMin.Add_Click({ $Window.WindowState = 'Minimized' })
    $BtnAuthClose.Add_Click({ $script:ReallyQuit = $true; $Window.Close() })
    $BtnAuthDe.Add_Click({ Set-AppLang 'de'; [void][SBLang]::Apply($AuthLayer) })
    $BtnAuthEn.Add_Click({ Set-AppLang 'en' })
    $UserCardBox.Add_MouseLeftButtonUp({ try { Show-AccountMenu } catch { } })
}

# normal app start - runs once the account is unlocked
function Start-Main {
        if ($script:Started) { return }
        $script:Started = $true
        try {
            Show-Overlay 'Scanning your hardware...'
            Run-Scan
            try { Set-UserCard } catch { }
            Show-Overlay 'Checking your current Windows settings...'
            foreach ($t in $Tweaks) { $t.Active = Test-Tweak $t }
            Show-Overlay 'Building optimizations...'
            foreach ($t in $Tweaks) { [void]$TweakGrid.Children.Add((New-TweakCard $t)) }
            foreach ($id in $FeaturedIds) { if ($TweakById.ContainsKey($id)) { [void]$FeatList.Children.Add((New-FeatRow $TweakById[$id])) } }
            foreach ($t in $Tweaks) { Update-TweakUI $t }
            Build-Chips
            Build-ProChips
            Apply-Filter
            Update-Columns
            Update-Stats
            Update-BackupPage
            try { Update-QuickPage } catch { }
            try { $script:ProcBaseline = @(Get-Process).Count } catch { }
            Write-Log "Silvan Boost $AppVersion started on $($HW.CpuName) / $($HW.GpuName)."
            Start-Metrics
            try { Initialize-Macros } catch { Write-Log "Macro engine error: $_" }
            try { Update-BenchUI; Build-History } catch { }
            Set-Status 'Ready - your PC has been scanned.'
            if ($JustUpdated -and $State.misc.ContainsKey('UpdFrom')) { Show-UpdatedNotice }
            Start-UpdateCheck
        } catch {
            Write-Log "Startup error: $($_.Exception.Message)"
            Set-Status "Startup error: $($_.Exception.Message)" 'err'
        }
        Hide-Overlay
        if ([SBLang]::Lang -eq 'de') { try { [void][SBLang]::Apply($Window) } catch { } }
        if (-not $State.misc['TourDone']) { try { Start-Tour } catch { Write-Log "Tour error: $_" } }
}


# ------------------------------------------------------------------ build window + wire events
try {
    $script:Window = [System.Windows.Markup.XamlReader]::Parse($Xaml)
    foreach ($m in [regex]::Matches($Xaml, 'x:Name="(\w+)"')) {
        $nm = $m.Groups[1].Value
        $el = $Window.FindName($nm)
        if ($el) { Set-Variable -Name $nm -Value $el -Scope Script }
    }
    try { Import-LangData; $lg = [string]$State.misc['Lang']; if (-not $lg) { $lg = Get-DefaultLang }; Set-AppLang $lg -NoSave } catch { Write-Log "Language setup error: $_" }
    try { Initialize-AuthEvents } catch { Write-Log "Account setup error: $_" }
    try { $Window.Icon = Get-LogoImage 256 } catch { }
    $AboutVer.Text = "Version $AppVersion  -  $($Tweaks.Count) optimizations and tools"
    $SideVer.Text = "v$AppVersion  -  FPS Optimizer"
    try {
        $wa = [System.Windows.SystemParameters]::WorkArea
        if ($Window.Width -gt $wa.Width - 20) { $Window.Width = [Math]::Max($Window.MinWidth, $wa.Width - 20) }
        if ($Window.Height -gt $wa.Height - 20) { $Window.Height = [Math]::Max($Window.MinHeight, $wa.Height - 20) }
    } catch { }
    if ($LauncherPath) { Write-Log "Started from $LauncherPath" }

    $NavHome.Add_Checked({ Show-Page 'Home' })
    $NavScan.Add_Checked({ Show-Page 'Scan' })
    $NavTweaks.Add_Checked({ Show-Page 'Tweaks' })
    $NavGames.Add_Checked({ Show-Page 'Games' })
    $NavApps.Add_Checked({ Show-Page 'Apps' })
    $NavPro.Add_Checked({ Show-Page 'Pro' })
    $NavProc.Add_Checked({ Show-Page 'Proc' })
    $NavPing.Add_Checked({ Show-Page 'Ping' })
    $AppTabBloat.Add_Checked({ if ($script:Started) { Show-AppsTab 'bloat' } })
    $AppTabAll.Add_Checked({ Show-AppsTab 'all' })
    $AppTabRec.Add_Checked({ Show-AppsTab 'rec' })
    $AppFltAll.Add_Checked({ $script:AppFilter = 'all'; if ($InstLoaded) { Show-InstalledApps } })
    $AppFltProg.Add_Checked({ $script:AppFilter = 'prog'; if ($InstLoaded) { Show-InstalledApps } })
    $AppFltStore.Add_Checked({ $script:AppFilter = 'store'; if ($InstLoaded) { Show-InstalledApps } })
    $AppSortName.Add_Checked({ $script:AppSort = 'name'; if ($InstLoaded) { Show-InstalledApps } })
    $AppSortSize.Add_Checked({ $script:AppSort = 'size'; if ($InstLoaded) { Show-InstalledApps } })
    $AppSortDate.Add_Checked({ $script:AppSort = 'date'; if ($InstLoaded) { Show-InstalledApps } })
    $AppSearch.Add_TextChanged({ if ($InstLoaded) { Show-InstalledApps } })
    $BtnAppsRefresh.Add_Click({ Load-InstalledApps })
    $BtnUpdCheck.Add_Click({ try { Start-UpdateCheck -Manual } catch { Write-Log "Update check error: $_" } })
    $BtnUpdNow.Add_Click({ try { Install-Update $PendingUpdate } catch { Write-Log "Update error: $_"; Hide-Overlay } })
    $UpdAuto.IsChecked = ($State.misc['AutoUpdate'] -ne $false)
    $UpdAuto.Add_Click({ $State.misc['AutoUpdate'] = [bool]$UpdAuto.IsChecked; Save-State })
    $NavInput.Add_Checked({ Show-Page 'Input' })
    Register-MacroEvents
    Register-TourEvents
    Register-FeatureEvents
    try { Initialize-Tray } catch { Write-Log "Tray icon error: $_" }
    $BtnPingTest.Add_Click({ try { Invoke-PingTest } catch { Write-Log "Ping test error: $_"; Hide-Overlay } })
    $BtnPingBoost.Add_Click({ try { Invoke-PingBoost } catch { Write-Log "Ping boost error: $_"; Hide-Overlay } })
    $BtnRoute.Add_Click({ try { Invoke-RouteTest '1.1.1.1' } catch { Write-Log "Route error: $_"; Hide-Overlay } })
    $BtnValve.Add_Click({ try { Test-ValveServers } catch { Write-Log "Valve error: $_"; Hide-Overlay } })
    $BtnBw.Add_Click({ try { Invoke-BandwidthScan } catch { Write-Log "Bandwidth error: $_"; Hide-Overlay } })
    $BtnWifiScan.Add_Click({ try { Invoke-WifiScan } catch { Write-Log "Wi-Fi scan error: $_" } })
    $BtnMtu.Add_Click({ try { Invoke-MtuTest } catch { Write-Log "MTU error: $_"; Hide-Overlay } })
    $BtnMtuApply.Add_Click({
        try {
            if (-not (Ensure-RestorePoint)) { return }
            Set-AdapterMtu $MtuFound
            $MtuRes.Text = "Adapter MTU set to $MtuFound."; $BtnMtuApply.Visibility = 'Collapsed'; $BtnMtuReset.Visibility = 'Visible'
        } catch { Show-Msg "Could not set the MTU: $($_.Exception.Message)" 'Silvan Boost' 'OK' 'Error' | Out-Null } })
    $BtnMtuReset.Add_Click({ try { Reset-AdapterMtu; $MtuRes.Text = 'Adapter MTU restored to its previous value.'; $BtnMtuReset.Visibility = 'Collapsed' } catch { } })
    $BtnNetQuick.Add_Click({ try { Invoke-NetQuickFix } catch { Hide-Overlay } })
    $BtnNetReset.Add_Click({ try { Invoke-NetFullReset } catch { Hide-Overlay } })
    $GameNetToggle.IsChecked = ($State.misc['GameNetMode'] -eq $true)
    $GameNetToggle.Add_Click({
        $State.misc['GameNetMode'] = [bool]$GameNetToggle.IsChecked; Save-State
        $GameNetRes.Text = $(if ($GameNetToggle.IsChecked) { 'On - keep Silvan Boost open (minimized is fine) while you play.' } else { 'Off.' })
        Write-Log ("Game network mode setting: " + [bool]$GameNetToggle.IsChecked) })
    $BtnDnsReset.Add_Click({
        try {
            Reset-DnsAll
            $cur = @(Get-ActiveDns)
            foreach ($x in $DnsResults) { $x.Current = ($cur.Count -gt 0 -and $x.Ip -eq [string]$cur[0]) }
            Show-DnsResults; Set-Status 'DNS reset to your previous / automatic setting'
        } catch { Write-Log "DNS reset error: $_" } })
    $BtnInputMax.Add_Click({ try { Invoke-InputMax } catch { Write-Log "Input max error: $_"; Hide-Overlay } })
    $BtnPollTest.Add_Click({ Start-PollTest })
    $BtnProcRefresh.Add_Click({ Load-ProcPage })
    $BtnProcReduce.Add_Click({ try { Invoke-ReduceProcesses } catch { Write-Log "Reduce error: $_"; Hide-Overlay } })
    $BtnProcSelRec.Add_Click({ foreach ($r in $ProcRows) { if ($r.Toggle) { $r.Toggle.IsChecked = $r.Rec } }; Update-ProcCount })
    $BtnProcClose.Add_Click({ try { $n = Close-SelectedProcs; if ($n -gt 0) { Start-Sleep -Milliseconds 800; [void](Update-ProcStats); Build-ProcList; Set-Status "Closed $n process(es)" } } catch { Write-Log "Close error: $_" } })
    $NavLive.Add_Checked({ Show-Page 'Live' })
    $BtnProOpen.Add_Click({ $nm = $ProTitle.Text; Start-Process ('https://prosettings.net/?s=' + [uri]::EscapeDataString($nm)) })
    $BtnProOptimize.Add_Click({ try { if (-not $GamesLoaded) { Load-Games }; Invoke-GamePreset (Get-Game $ProSel) } catch { Write-Log "Pro optimize error: $_" } })
    $NavBackup.Add_Checked({ Show-Page 'Backup' })
    $BtnGamesRescan.Add_Click({ Load-Games })
    $BtnAddGame.Add_Click({ try { Add-CustomGame } catch { Write-Log "Add game error: $_" } })
    $BtnAppsRec.Add_Click({ Select-Apps 'rec' })
    $BtnAppsNone.Add_Click({ Select-Apps 'none' })
    $BtnAppsRemove.Add_Click({ try { Remove-SelectedApps } catch { Write-Log "App removal error: $_" } })
    $NavAbout.Add_Checked({ Show-Page 'About' })

    $BtnMin.Add_Click({ $Window.WindowState = 'Minimized' })
    $BtnMax.Add_Click({ if ($Window.WindowState -eq 'Maximized') { $Window.WindowState = 'Normal' } else { $Window.WindowState = 'Maximized' } })
    $BtnClose.Add_Click({ $Window.Close() })
    $Window.Add_StateChanged({
        if ($Window.WindowState -eq 'Maximized') { $RootBorder.Margin = [System.Windows.Thickness]::new(7); $BtnMax.Content = [string][char]0xE923 }
        else { $RootBorder.Margin = [System.Windows.Thickness]::new(0); $BtnMax.Content = [string][char]0xE922 }
    })
    $Window.Add_SizeChanged({ try { Update-Columns; Update-Stats } catch { } })

    $BtnViewTweaks.Add_Click({ $NavTweaks.IsChecked = $true })
    $BtnManage.Add_Click({ $NavTweaks.IsChecked = $true })
    $BtnViewScan.Add_Click({ $NavScan.IsChecked = $true })
    $ScScan.Add_Click({ $NavScan.IsChecked = $true })
    $BtnQuickBoost.Add_Click({ $NavQuick.IsChecked = $true })
    $NavQuick.Add_Checked({ Show-Page 'Quick' })
    $QbSafe.Add_Checked({ $script:QbSel = 'safe'; if ($script:Started) { Update-QuickPage } })
    $QbComp.Add_Checked({ $script:QbSel = 'comp'; if ($script:Started) { Update-QuickPage } })
    $QbMax.Add_Checked({ $script:QbSel = 'max'; if ($script:Started) { Update-QuickPage } })
    $BtnQbApply.Add_Click({ try { Invoke-QuickApply } catch { Write-Log "Quick Boost error: $_"; Hide-Overlay } })
    $BtnQbShow.Add_Click({
        if ($QbListBox.Visibility -eq 'Visible') { $QbListBox.Visibility = 'Collapsed'; $BtnQbShow.Content = 'Show what will change' }
        else { $QbListBox.Visibility = 'Visible'; $BtnQbShow.Content = 'Hide details'; Invoke-AnimateIn $QbListBox 6 220 } })
    $BtnNextGo.Add_Click({ if ($NextAction -eq 'quick') { $NavQuick.IsChecked = $true } else { $NavScan.IsChecked = $true } })
    Initialize-NavCats
    $pressDown = [System.Windows.Input.MouseButtonEventHandler] { param($s, $e) try { Invoke-Press $s 0.97 } catch { } }
    $pressUp = [System.Windows.Input.MouseButtonEventHandler] { param($s, $e) try { Invoke-Press $s 1 } catch { } }
    $pressLeave = [System.Windows.Input.MouseEventHandler] { param($s, $e) try { if ($s.RenderTransform -is [System.Windows.Media.ScaleTransform] -and $s.RenderTransform.ScaleX -lt 1) { Invoke-Press $s 1 } } catch { } }
    [System.Windows.EventManager]::RegisterClassHandler([System.Windows.Controls.Primitives.ButtonBase], [System.Windows.UIElement]::PreviewMouseLeftButtonDownEvent, $pressDown)
    [System.Windows.EventManager]::RegisterClassHandler([System.Windows.Controls.Primitives.ButtonBase], [System.Windows.UIElement]::PreviewMouseLeftButtonUpEvent, $pressUp)
    [System.Windows.EventManager]::RegisterClassHandler([System.Windows.Controls.Primitives.ButtonBase], [System.Windows.UIElement]::MouseLeaveEvent, $pressLeave)
    $pulse = New-Anim 0.35 1000 0 1; $pulse.AutoReverse = $true; $pulse.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
    $LivePulse.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $pulse)
    $BtnPresetSafe.Add_Click({ try { Invoke-Preset 'safe' } catch { Write-Log "UI error: $_" } })
    $BtnPresetMax.Add_Click({ try { Invoke-Preset 'max' } catch { Write-Log "UI error: $_" } })
    $BtnRevertAll.Add_Click({ try { Invoke-RevertAll } catch { Write-Log "UI error: $_" } })
    $BpRevertAll.Add_Click({ try { Invoke-RevertAll } catch { Write-Log "UI error: $_" } })
    $ScClean.Add_Click({ Invoke-ActionTweak $TweakById['clean-temp'] })
    $ScDns.Add_Click({ Invoke-ActionTweak $TweakById['flush-dns'] })

    $restoreHandler = {
        Show-Overlay 'Creating a System Restore point...'
        $ok = New-RestorePoint
        Hide-Overlay
        if ($ok) { $script:RPChecked = $true; $script:RPOk = $true; Set-Status 'System Restore point created.'; Show-Msg 'System Restore point created.' | Out-Null }
        else { Set-Status 'Restore point failed.' 'err'; Show-Msg 'Windows could not create a restore point. Make sure System Protection is turned on for your system drive (search "Create a restore point" in Start).' 'Silvan Boost' 'OK' 'Warning' | Out-Null }
    }
    $ScRestore.Add_Click($restoreHandler)
    $BpCreate.Add_Click($restoreHandler)
    $BpOpenRestore.Add_Click({ Start-Process 'rstrui.exe' })
    $BpOpenFolder.Add_Click({ Start-Process 'explorer.exe' -ArgumentList "`"$DataDir`"" })
    $BtnRescan.Add_Click({ Show-Overlay 'Scanning your hardware...'; try { Run-Scan; Update-Stats } catch { Write-Log "Scan error: $_" }; Hide-Overlay; Set-Status 'Scan complete.' })
    $BtnRestart.Add_Click({
        $r = Show-Msg 'Restart your PC now? Save your work first.' 'Restart' 'YesNo' 'Question'
        if ([string]$r -eq 'Yes') { shutdown.exe /r /t 5 /c "Silvan Boost: restarting to finish optimizations" }
    })
    $SearchBox.Add_TextChanged({ Apply-Filter })

    $Window.Add_ContentRendered({
        if ($script:GateStarted) { return }
        $script:GateStarted = $true
        try { Start-AuthGate } catch { Write-Log "Account error: $($_.Exception.Message)"; try { Show-AuthLogin } catch { } }
    })

    $Window.Add_Closed({ try { if ($Auth.temp) { Clear-Auth } } catch { } })

    $Window.Add_Closed({
        $Sync.Run = $false
        try { [void][SBRaw]::Stop() } catch { }
        try { Exit-AutoGameMode } catch { }
        try { if ($Tray) { $Tray.Visible = $false; $Tray.Dispose() } } catch { }
        try { if ($script:MacroTimer) { $MacroTimer.Stop() }; [SBMacro]::Stop() } catch { }
        try { Exit-GameNetMode } catch { }
        Stop-PresentMon
        if (Test-Path -LiteralPath $PresentMonPath) { try { Start-Process -FilePath $PresentMonPath -ArgumentList '--terminate_existing_session --session_name SilvanBoostPM' -WindowStyle Hidden } catch { } }
        if ($script:Timer) { $Timer.Stop() }
        try { if ($script:WpfApp) { $WpfApp.Shutdown() } } catch { }
    })

    # Application.Run (instead of ShowDialog) so the window can hide to the tray
    $script:WpfApp = [System.Windows.Application]::Current
    if (-not $WpfApp) { $script:WpfApp = New-Object System.Windows.Application }
    $WpfApp.ShutdownMode = [System.Windows.ShutdownMode]::OnExplicitShutdown
    [void]$WpfApp.Run($Window)
} catch {
    Write-Log "Fatal: $($_.Exception.Message)"
    [System.Windows.MessageBox]::Show("Silvan Boost could not start:`n`n$($_.Exception.Message)`n`nLog: $LogFile", 'Silvan Boost', 'OK', 'Error') | Out-Null
    exit 1
}
