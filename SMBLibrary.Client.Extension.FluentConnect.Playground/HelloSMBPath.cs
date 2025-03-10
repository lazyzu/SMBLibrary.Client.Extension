using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.FluentConnect.Playground
{
    public class HelloSMBPath
    {
        [Test]
        public async Task SMBPath_ParseFrom()
        {
            var (isParsed, samplePath, parsedError) = SMBPath.ParseFrom(@"\\127.0.0.1\share\hello\sample.txt");
            if (isParsed)
            {
                await Assert.That(samplePath.HostName).IsEqualTo("127.0.0.1");
                await Assert.That(samplePath.ShareName).IsEqualTo("share");
                await Assert.That(samplePath.Path).IsEqualTo(@"hello\sample.txt");
                await Assert.That(samplePath.ToString()).IsEqualTo(@"\\127.0.0.1\share\hello\sample.txt");
            }
            else Assert.Fail(parsedError.Message);
        }

        [Test]
        public async Task SMBPath_ParseFrom_PathSeparatorReplace()
        {
            var (isParsed, samplePath, parsedError) = SMBPath.ParseFrom(@"//127.0.0.1/share/hello/sample.txt");
            if (isParsed)
            {
                await Assert.That(samplePath.HostName).IsEqualTo("127.0.0.1");
                await Assert.That(samplePath.ShareName).IsEqualTo("share");
                await Assert.That(samplePath.Path).IsEqualTo(@"hello\sample.txt");
                await Assert.That(samplePath.ToString()).IsEqualTo(@"\\127.0.0.1\share\hello\sample.txt");
            }
            else Assert.Fail(parsedError.Message);
        }

        [Test]
        public async Task SMBPath_ParseFrom_WithParentDirectory()
        {
            var (isParsed, samplePath, parsedError) = SMBPath.ParseFrom(@"\\127.0.0.1\share\hello\..\sample.txt");
            if (isParsed)
            {
                await Assert.That(samplePath.HostName).IsEqualTo("127.0.0.1");
                await Assert.That(samplePath.ShareName).IsEqualTo("share");
                await Assert.That(samplePath.Path).IsEqualTo(@"hello\..\sample.txt");
            }
            else Assert.Fail(parsedError.Message);
        }


        [Test]
        public async Task SMBPath_RelativePath()
        {
            var (isParsed, samplePath, parsedError) = SMBPath.ParseFrom(@"\\127.0.0.1\share\hello\sample.txt");
            if (isParsed)
            {
                (isParsed, var relativeSamplePath, parsedError) = samplePath.GetRelative(@"..\relativeSample.txt");
                if (isParsed)
                {
                    await Assert.That(relativeSamplePath.HostName).IsEqualTo("127.0.0.1");
                    await Assert.That(relativeSamplePath.ShareName).IsEqualTo("share");
                    await Assert.That(relativeSamplePath.Path).IsEqualTo(@"hello\relativeSample.txt");
                }
                else Assert.Fail(parsedError.Message);
            }
            else Assert.Fail(parsedError.Message);
        }
    }
}
