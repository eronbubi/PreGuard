using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

namespace PreGuard
{
    static class Icons
    {
        static readonly Color ActiveTop = Color.FromArgb(0x3D, 0x8B, 0xFD), ActiveBottom = Color.FromArgb(0x15, 0x4E, 0xC1);
        static readonly Color PausedTop = Color.FromArgb(0xA0, 0xA7, 0xB0), PausedBottom = Color.FromArgb(0x5F, 0x66, 0x70);

        public static Bitmap Draw(int size, bool paused)
        {
            var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                g.Clear(Color.Transparent);
                float s = size;
                using (var path = Shield(s))
                using (var brush = new LinearGradientBrush(new RectangleF(0, 0, s, s),
                           paused ? PausedTop : ActiveTop, paused ? PausedBottom : ActiveBottom, 90f))
                    g.FillPath(brush, path);
                using (var pen = new Pen(Color.White, Math.Max(1.6f, s * 0.11f)))
                {
                    pen.StartCap = LineCap.Round;
                    pen.EndCap = LineCap.Round;
                    pen.LineJoin = LineJoin.Round;
                    if (paused)
                    {
                        g.DrawLine(pen, s * 0.41f, s * 0.34f, s * 0.41f, s * 0.64f);
                        g.DrawLine(pen, s * 0.59f, s * 0.34f, s * 0.59f, s * 0.64f);
                    }
                    else
                    {
                        g.DrawLines(pen, new[] { new PointF(s * 0.31f, s * 0.49f), new PointF(s * 0.45f, s * 0.63f), new PointF(s * 0.70f, s * 0.36f) });
                    }
                }
            }
            return bmp;
        }

        static GraphicsPath Shield(float s)
        {
            var p = new GraphicsPath();
            float left = s * 0.12f, right = s * 0.88f, top = s * 0.05f, mid = s * 0.5f, bottom = s * 0.96f, shoulder = s * 0.18f, waist = s * 0.50f;
            p.AddLine(mid, top, right, shoulder);
            p.AddLine(right, shoulder, right, waist);
            p.AddBezier(right, waist, right, s * 0.74f, s * 0.70f, s * 0.87f, mid, bottom);
            p.AddBezier(mid, bottom, s * 0.30f, s * 0.87f, left, s * 0.74f, left, waist);
            p.AddLine(left, waist, left, shoulder);
            p.CloseFigure();
            return p;
        }

        public static Icon Create(int size, bool paused)
        {
            using (var bmp = Draw(size, paused))
                return Icon.FromHandle(bmp.GetHicon());
        }

        // Writes a multi-resolution .ico with PNG payloads (supported since Windows Vista).
        public static void SaveIco(string path)
        {
            File.WriteAllBytes(path, BuildIco(new[] { 16, 20, 24, 32, 40, 48, 64, 256 }, false));
        }

        static byte[] BuildIco(int[] sizes, bool paused)
        {
            var images = new byte[sizes.Length][];
            for (int i = 0; i < sizes.Length; i++)
                using (var bmp = Draw(sizes[i], paused))
                using (var ms = new MemoryStream())
                {
                    bmp.Save(ms, ImageFormat.Png);
                    images[i] = ms.ToArray();
                }
            using (var ms = new MemoryStream())
            using (var w = new BinaryWriter(ms))
            {
                w.Write((ushort)0); w.Write((ushort)1); w.Write((ushort)sizes.Length);
                int offset = 6 + 16 * sizes.Length;
                for (int i = 0; i < sizes.Length; i++)
                {
                    w.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
                    w.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
                    w.Write((byte)0); w.Write((byte)0);
                    w.Write((ushort)1); w.Write((ushort)32);
                    w.Write(images[i].Length);
                    w.Write(offset);
                    offset += images[i].Length;
                }
                foreach (var img in images) w.Write(img);
                w.Flush();
                return ms.ToArray();
            }
        }
    }
}
