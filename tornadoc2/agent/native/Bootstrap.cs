using System;
using System.Reflection;
using System.Text;

namespace TornadoBootstrap
{
    public static class Entry
    {
        public static int Run(string arg)
        {
            if (string.IsNullOrEmpty(arg)) return 1;
            int sep = arg.IndexOf('|');
            if (sep < 0) return 1;
            int sep2 = arg.IndexOf('|', sep + 1);
            if (sep2 < 0) return 1;

            byte[] asmBytes;
            try { asmBytes = Convert.FromBase64String(arg.Substring(0, sep)); }
            catch (FormatException) { return 1; }

            string outputPath = arg.Substring(sep2 + 1);
            string rawArgs = arg.Substring(sep + 1, sep2 - sep - 1);
            byte[] argBytes;
            try
            {
                argBytes = string.IsNullOrEmpty(rawArgs)
                    ? new byte[0]
                    : Convert.FromBase64String(rawArgs);
            }
            catch (FormatException) { return 1; }

            string argsString = argBytes.Length == 0
                ? ""
                : Encoding.UTF8.GetString(argBytes);

            Assembly asm;
            try
            {
                asm = Assembly.Load(asmBytes);
            }
            catch (Exception ex)
            {
                // Best-effort: write the reason to the capture
                // file before returning. The loader will read the
                // file on the parent side regardless of the
                // bootstrap's return code, so this is what the
                // operator sees next to exit 2.
                try
                {
                    if (!string.IsNullOrEmpty(outputPath))
                    {
                        System.IO.File.AppendAllText(
                            outputPath,
                            "[bootstrap] Assembly.Load failed: " +
                            ex.GetType().Name + ": " +
                            ex.Message + Environment.NewLine);
                    }
                }
                catch { /* nothing more to try */ }
                return 2;
            }

            MethodInfo entry = asm.EntryPoint;
            if (entry == null)
            {
                try
                {
                    if (!string.IsNullOrEmpty(outputPath))
                    {
                        System.IO.File.AppendAllText(
                            outputPath,
                            "[bootstrap] assembly has no declared " +
                            "entry point; the loader needs an " +
                            "explicit type and method, or a Donut-" +
                            "wrapped build." + Environment.NewLine);
                    }
                }
                catch { }
                return 3;
            }

            string[] argv = string.IsNullOrEmpty(argsString)
                ? new string[0]
                : SplitArgs(argsString);

            object[] invokeArgs = entry.GetParameters().Length == 0
                ? null
                : new object[] { argv };

            // Some tools read Environment.GetCommandLineArgs()
            // instead of the Main(string[]) parameter. Set the
            // process's command line to the target's arguments
            // before invoking, so those tools see what the
            // operator typed.
            try
            {
                var cmdLineProp = typeof(Environment).GetProperty(
                    "CommandLine",
                    BindingFlags.Static | BindingFlags.Public |
                    BindingFlags.NonPublic);
                if (cmdLineProp != null && cmdLineProp.CanWrite)
                {
                    cmdLineProp.SetValue(null,
                        "target.exe " + argsString, null);
                }
            }
            catch { /* best-effort; the target may still work via argv */ }

            // Redirect the target's Console output to a file the
            // loader reads after ExecuteInDefaultAppDomain returns.
            // Without this, a beacon process with no attached
            // console discards everything the target writes.
            System.IO.TextWriter originalOut = Console.Out;
            System.IO.TextWriter originalErr = Console.Error;
            System.IO.StreamWriter capture = null;
            try
            {
                if (!string.IsNullOrEmpty(outputPath))
                {
                    capture = new System.IO.StreamWriter(
                        outputPath, false, new UTF8Encoding(false));
                    capture.AutoFlush = true;
                    Console.SetOut(capture);
                    Console.SetError(capture);
                }
            }
            catch (Exception)
            {
                // If the file cannot be opened, fall through with
                // the original writers; the loader will report an
                // empty capture rather than fail the run.
                capture = null;
            }

            object result;
            int rc;
            try
            {
                result = entry.Invoke(null, invokeArgs);
                rc = (result is int) ? (int)result : 0;

                if (capture != null)
                    capture.WriteLine("[bootstrap] target returned, rc=" + rc);
            }
            catch (TargetInvocationException tie)
            {
                if (capture != null)
                    capture.WriteLine("[bootstrap] target threw: " + tie.InnerException);
                rc = 4;
            }
            catch (Exception ex)
            {
                if (capture != null)
                    capture.WriteLine("[bootstrap] invoke failed: " + ex);
                rc = 5;
            }
            finally
            {
                if (capture != null)
                {
                    Console.SetOut(originalOut);
                    Console.SetError(originalErr);
                    try { capture.Flush(); capture.Dispose(); } catch { }
                }
            }

            return rc;

            if (result is int) return (int)result;
            return 0;
        }

        private static string[] SplitArgs(string s)
        {
            var list = new System.Collections.Generic.List<string>();
            var sb = new StringBuilder();
            bool inQuote = false;
            foreach (char c in s)
            {
                if (c == '"') { inQuote = !inQuote; continue; }
                if (!inQuote && char.IsWhiteSpace(c))
                {
                    if (sb.Length > 0) { list.Add(sb.ToString()); sb.Clear(); }
                    continue;
                }
                sb.Append(c);
            }
            if (sb.Length > 0) list.Add(sb.ToString());
            return list.ToArray();
        }
    }
}