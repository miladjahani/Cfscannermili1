# اسکنر کلودفلر (Ultimate Proxy & Cloudflare IP Scanner)

اپلیکیشن اندروید برای اسکن و تست کانفیگ‌های پروکسی (VLESS / VMess / Trojan / Shadowsocks) و رنج‌های آی‌پی کلودفلر، ساخته‌شده با KivyMD.

## ساختار پروژه
```
.
├── main.py                       # کد اصلی اپلیکیشن
├── buildozer.spec                # تنظیمات ساخت اندروید (Buildozer)
└── .github/workflows/build.yml   # پایپ‌لاین CI برای ساخت خودکار APK
```

## ساخت محلی (Local build)
```bash
pip install buildozer cython==0.29.36
buildozer android debug
```

## ساخت خودکار (GitHub Actions)
با هر push به شاخه `main`، اکشن گیت‌هاب به‌صورت خودکار APK را می‌سازد و به‌عنوان Artifact بارگذاری می‌کند (تب Actions → آخرین اجرا → Artifacts).
