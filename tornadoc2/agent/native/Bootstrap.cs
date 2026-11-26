using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace TornadoBootstrap
{
    /// <summary>
    /// Managed bootstrap invoked by ICLRRuntimeHost::
    /// ExecuteInDefaultAppDomain. Input is
    /// "&lt;b64 assembly&gt;|&lt;b64 args&gt;|&lt;capture path&gt;".
    /// The assembly is loaded from memory and its entry point is
    /// invoked with the operator's arguments. Console output is
    /// redirected to the capture file because the host process has
    /// no console.
    /// </summary>
    public static class Entry
    {
        private const int RcParse = 1;
        private const int RcLoad = 2;
        private const int RcEntry = 3;
        private const int RcTarget = 4;
        private const int RcInvoke = 5;
        private const int RcSignature = 6;

        public static int Run(string arg)
        {
            string outputPath = "";
            StreamWriter capture = null;
            TextWriter originalOut = Console.Out;
            TextWriter originalErr = Console.Error;

            try
            {
                string rawArgs, asmB64, typeB64, methodB64;
                if (!Parse(arg, out asmB64, out rawArgs, out outputPath,
                          out typeB64, out methodB64))
                    return Fail(ref capture, outputPath,
                        originalOut, originalErr, RcParse,
                        "malformed bootstrap payload");

                capture = OpenCapture(outputPath);
                if (capture != null)
                {
                    Console.SetOut(capture);
                    Console.SetError(capture);
                }

                byte[] asmBytes;
                try
                {
                    asmBytes = Convert.FromBase64String(asmB64);
                }
                catch (FormatException)
                {
                    return Fail(ref capture, outputPath,
                        originalOut, originalErr, RcParse,
                        "assembly is not valid base64");
                }

                string argsString = "";
                if (!string.IsNullOrEmpty(rawArgs))
                {
                    try
                    {
                        argsString = Encoding.UTF8.GetString(
                            Convert.FromBase64String(rawArgs));
                    }
                    catch (FormatException)
                    {
                        return Fail(ref capture, outputPath,
                            originalOut, originalErr, RcParse,
                            "arguments are not valid base64");
                    }
                }

                // Dependency assemblies are not embedded in the
                // payload; resolve them from the directory the
                // bootstrap was loaded from.
                AppDomain.CurrentDomain.AssemblyResolve +=
                    ResolveFromBaseDirectory;

                Assembly asm;
                try
                {
                    asm = Assembly.Load(asmBytes);
                }
                catch (Exception ex)
                {
                    return Fail(ref capture, outputPath,
                        originalOut, originalErr, RcLoad,
                        "Assembly.Load failed: " + Describe(ex));
                }

                string entryType = DecodeText(typeB64);
                string entryMethod = DecodeText(methodB64);
                MethodInfo entry = !string.IsNullOrEmpty(entryType) &&
                                   !string.IsNullOrEmpty(entryMethod)
                    ? FindNamed(asm, entryType, entryMethod)
                    : FindEntry(asm);
                if (entry == null)
                {
                    return Fail(ref capture, outputPath,
                        originalOut, originalErr, RcEntry,
                        "assembly has no runnable entry point " +
                        "(no declared Main and no static Main)");
                }

                string[] argv = string.IsNullOrEmpty(argsString)
                    ? new string[0]
                    : SplitArgs(argsString);

                SetCommandLine(argsString);

                ParameterInfo[] parameters = entry.GetParameters();
                object[] invokeArgs;
                if (parameters.Length == 0)
                {
                    invokeArgs = null;
                }
                else if (parameters.Length == 1 &&
                         parameters[0].ParameterType == typeof(string[]))
                {
                    invokeArgs = new object[] { argv };
                }
                else if (parameters.Length == 1 &&
                         parameters[0].ParameterType == typeof(string))
                {
                    invokeArgs = new object[] { argsString };
                }
                else
                {
                    return Fail(ref capture, outputPath,
                        originalOut, originalErr, RcSignature,
                        "entry point signature is not " +
                        "Main(), Main(string), or Main(string[])");
                }

                object target = null;
                if (!entry.IsStatic)
                {
                    try
                    {
                        target = Activator.CreateInstance(
                            entry.DeclaringType);
                    }
                    catch (Exception ex)
                    {
                        return Fail(ref capture, outputPath,
                            originalOut, originalErr, RcInvoke,
                            "cannot construct entry type: " +
                            Describe(ex));
                    }
                }

                object result;
                try
                {
                    result = entry.Invoke(target, invokeArgs);
                }
                catch (TargetInvocationException tie)
                {
                    return Fail(ref capture, outputPath,
                        originalOut, originalErr, RcTarget,
                        "target threw: " +
                        Describe(tie.InnerException ?? tie));
                }
                catch (Exception ex)
                {
                    return Fail(ref capture, outputPath,
                        originalOut, originalErr, RcInvoke,
                        "invoke failed: " + Describe(ex));
                }

                int rc = Complete(result);
                if (capture != null)
                    capture.WriteLine("[bootstrap] target returned, rc=" + rc);
                return rc;
            }
            catch (Exception ex)
            {
                return Fail(ref capture, outputPath,
                    originalOut, originalErr, RcInvoke,
                    "bootstrap failure: " + Describe(ex));
            }
            finally
            {
                Restore(capture, originalOut, originalErr);
            }
        }

        private static bool Parse(string arg, out string asmB64,
                                  out string rawArgs, out string outputPath,
                                  out string typeB64, out string methodB64)
        {
            asmB64 = rawArgs = outputPath = typeB64 = methodB64 = "";
            if (string.IsNullOrEmpty(arg)) return false;
            string[] p = arg.Split(new char[] { '|' }, 5);
            if (p.Length < 3) return false;
            asmB64 = p[0];
            rawArgs = p[1];
            outputPath = p[2];
            if (p.Length > 3) typeB64 = p[3];
            if (p.Length > 4) methodB64 = p[4];
            return asmB64.Length > 0;
        }

        private static string DecodeText(string b64)
        {
            if (string.IsNullOrEmpty(b64)) return "";
            try { return Encoding.UTF8.GetString(
                      Convert.FromBase64String(b64)); }
            catch { return ""; }
        }

        private static MethodInfo FindNamed(Assembly asm, string type,
                                            string method)
        {
            try
            {
                Type t = asm.GetType(type, false);
                if (t == null) return null;
                return t.GetMethod(method,
                    BindingFlags.Static | BindingFlags.Instance |
                    BindingFlags.Public | BindingFlags.NonPublic);
            }
            catch { return null; }
        }

        private static StreamWriter OpenCapture(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            try
            {
                var w = new StreamWriter(path, false,
                    new UTF8Encoding(false));
                w.AutoFlush = true;
                return w;
            }
            catch
            {
                return null;
            }
        }

        private static void Restore(StreamWriter capture,
                                    TextWriter originalOut,
                                    TextWriter originalErr)
        {
            try { Console.SetOut(originalOut); } catch { }
            try { Console.SetError(originalErr); } catch { }
            if (capture != null)
            {
                try { capture.Flush(); } catch { }
                try { capture.Dispose(); } catch { }
            }
        }

        private static int Fail(ref StreamWriter capture, string outputPath,
                                TextWriter originalOut, TextWriter originalErr,
                                int code, string message)
        {
            try
            {
                if (capture != null)
                {
                    capture.WriteLine("[bootstrap] " + message);
                }
                else if (!string.IsNullOrEmpty(outputPath))
                {
                    File.AppendAllText(outputPath,
                        "[bootstrap] " + message + Environment.NewLine);
                }
            }
            catch { }
            return code;
        }

        private static MethodInfo FindEntry(Assembly asm)
        {
            try
            {
                MethodInfo declared = asm.EntryPoint;
                if (declared != null) return declared;
            }
            catch { }

            // DLLs compiled without /main: look for the conventional
            // static Main. Deterministic order keeps repeat runs
            // stable.
            Type[] types;
            try { types = asm.GetTypes(); }
            catch (ReflectionTypeLoadException e)
            {
                var list = new List<Type>();
                foreach (Type t in e.Types)
                    if (t != null) list.Add(t);
                types = list.ToArray();
            }
            Array.Sort(types, (a, b) =>
                string.CompareOrdinal(a.FullName, b.FullName));
            foreach (Type t in types)
            {
                MethodInfo m = t.GetMethod("Main",
                    BindingFlags.Static | BindingFlags.Public |
                    BindingFlags.NonPublic);
                if (m != null) return m;
            }
            return null;
        }

        private static int Complete(object result)
        {
            if (result is int) return (int)result;
            Task<int> ti = result as Task<int>;
            if (ti != null)
            {
                try
                {
                    if (!ti.Wait(TimeSpan.FromMinutes(10)))
                        return 7;
                    return ti.Result;
                }
                catch (AggregateException ae)
                {
                    throw ae.InnerException ?? ae;
                }
            }
            Task t = result as Task;
            if (t != null)
            {
                if (!t.Wait(TimeSpan.FromMinutes(10))) return 7;
                return 0;
            }
            return 0;
        }

        private static void SetCommandLine(string args)
        {
            // Environment.CommandLine is read-only publicly. Its
            // backing field differs between frameworks; best effort.
            string line = "target.exe " + args;
            foreach (string name in new[] {
                         "s_commandLine", "_commandLine" })
            {
                try
                {
                    FieldInfo f = typeof(Environment).GetField(
                        name, BindingFlags.Static | BindingFlags.NonPublic);
                    if (f != null && f.FieldType == typeof(string))
                    {
                        f.SetValue(null, line);
                        return;
                    }
                }
                catch { }
            }
        }

        private static Assembly ResolveFromBaseDirectory(
            object sender, ResolveEventArgs args)
        {
            try
            {
                string dir = AppDomain.CurrentDomain.BaseDirectory;
                if (string.IsNullOrEmpty(dir)) return null;
                string name = new AssemblyName(args.Name).Name + ".dll";
                string path = Path.Combine(dir, name);
                if (File.Exists(path)) return Assembly.LoadFrom(path);
            }
            catch { }
            return null;
        }

        private static string Describe(Exception ex)
        {
            if (ex == null) return "unknown";
            return ex.GetType().Name + ": " + ex.Message;
        }

        private static string[] SplitArgs(string s)
        {
            var list = new List<string>();
            var sb = new StringBuilder();
            bool inQuote = false;
            foreach (char c in s)
            {
                if (c == '"') { inQuote = !inQuote; continue; }
                if (!inQuote && char.IsWhiteSpace(c))
                {
                    if (sb.Length > 0)
                    {
                        list.Add(sb.ToString());
                        sb.Clear();
                    }
                    continue;
                }
                sb.Append(c);
            }
            if (sb.Length > 0) list.Add(sb.ToString());
            return list.ToArray();
        }
    }
}
