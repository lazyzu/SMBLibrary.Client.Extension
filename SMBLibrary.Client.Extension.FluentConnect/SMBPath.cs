using System;
using System.Text.RegularExpressions;

namespace SMBLibrary.Client.Extension.FluentConnect
{
    public class SMBPath
    {
        public readonly string HostName;
        public readonly string ShareName;
        public readonly string Path;

        private SMBPath(string hostName, string shareName, string path)
        {
            HostName = hostName;
            ShareName = shareName;
            Path = path;
        }

        public Result<SMBPath, Exception> GetRelative(string reference)
        {
            var _reference = reference?.Trim()?.Replace(@"/", @"\");

            if (string.IsNullOrEmpty(_reference)) return new SMBPath(HostName, ShareName, Path);
            else
            {
                var path = Path;
                var parts = _reference.Split(new char[] { '\\' });

                foreach (var part in parts)
                {
                    if (".".Equals(part)) { /*path = path;*/ }
                    else if ("..".Equals(part))
                    {
                        var lastSeparatorIndex = path.LastIndexOf('\\');
                        if (lastSeparatorIndex == -1) path = string.Empty;
                        else path = path.Substring(0, lastSeparatorIndex);
                    }
                    else if (string.IsNullOrEmpty(part) == false)
                    {
                        if (string.IsNullOrEmpty(path)) path = part;
                        else path = $"{path}\\{part}";
                    }
                }

                if (isPathHasError(path, out var error)) return error;
                else return new SMBPath(HostName, ShareName, path);
            }
        }

        public static Result<SMBPath, Exception> ParseFrom(string path)
        {
            var unixPath = path?.Trim()?.Replace("/", "\\");

            if (string.IsNullOrEmpty(unixPath)) return null;
            else
            {
                var pathMatchResult = PathRegex.Match(unixPath);
                if (pathMatchResult.Success)
                {
                    var hostName = pathMatchResult.Groups["HostName"].Value;
                    var shareName = pathMatchResult.Groups["ShareName"].Value;
                    var pathName = pathMatchResult.Groups["PathName"].Value;
                    if (string.IsNullOrEmpty(pathName) == false) pathName = pathName.Substring(1);  // remove start path separator

                    if (isPathHasError(pathName, out var error)) return error;
                    else return new SMBPath(hostName, shareName, pathName);
                }
                else return new ArgumentException($"{path} is not valid, check failed by regex: {PathRegex}");
            }
        }

        public override string ToString()
        {
            return $"\\\\{HostName}\\{ShareName}\\{Path}";
        }

        private static bool isPathHasError(string pathName, out Exception error)
        {
            error = null;

            if (pathName.EndsWith(".")) error = new ArgumentException($"{pathName} end with dot(.) maybe not able to access normally, please check https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/cannot-delete-file-folder-on-ntfs-file-system#cause-6-the-file-name-includes-an-invalid-name-in-the-win32-name-space");

            return error != null;
        }

        private static Regex PathRegex = new Regex(@"^\\\\(?<HostName>[a-zA-Z_\-\s0-9\.]+)(\\(?<ShareName>[^\\\/:""\*\?\<\>|]+))(?<PathName>(\\[^\\\/:""\*\?\<\>|]+)+)?\\?$");    // Revered characters: \, /, :, ", *, ?, <, >, |

        //public static readonly char[] PathSeparators = new char[]
        //{
        //            '\\',
        //            '/'
        //};
    }
}