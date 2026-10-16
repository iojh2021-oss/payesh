# پایش (Payesh)

رصد ترافیک اینترنت همهٔ برنامه‌های اندروید (سیستمی و غیرسیستمی) بدون نیاز به روت.

## امکانات
- نمایش مقصد (دامنه/آی‌پی)، پورت، پروتکل (TCP/UDP) و حجم ارسال/دریافت روبروی آیکون و نام هر برنامه
- تشخیص برنامه‌های **فعال**، **پیش‌زمینه / پس‌زمینه** و **در حال دانلود** (با سرعت)
- نمایش برنامه‌هایی که ترافیکی ندارند («بدون ترافیک»)
- فیلتر (فعال، دانلود، سیستمی، غیرسیستمی) و جستجو
- آدرس کامل (URL) برای ترافیک HTTP ساده؛ برای HTTPS فقط دامنه (SNI) دیده می‌شود

## روش کار
یک VPN محلی (`VpnService`) روی خود گوشی ساخته می‌شود. همهٔ بسته‌های IPv4 برنامه‌ها از آن می‌گذرند،
با `ConnectivityManager.getConnectionOwnerUid` به برنامهٔ صاحب اتصال نسبت داده می‌شوند و سپس با سوکت‌های محافظت‌شده
به اینترنت واقعی فرستاده می‌شوند. هیچ داده‌ای به سرور دیگری ارسال نمی‌شود.

## ساخت APK
گیت‌هاب اکشنز (`.github/workflows/build.yml`) با هر push روی `main` فایل APK می‌سازد:
Actions ← آخرین اجرا ← Artifacts ← `payesh-debug-apk`.

## پوش با Termux
```sh
pkg install git unzip
termux-setup-storage
cd ~ && unzip ~/storage/downloads/payesh.zip && cd payesh
git init && git branch -M main
git add . && git commit -m "Initial commit"
git remote add origin https://github.com/iojh2021-oss/payesh.git
git push -u origin main
```
(برای رمز، از Personal Access Token گیت‌هاب استفاده کن.)

## محدودیت‌ها
- فقط IPv4 رصد می‌شود (IPv6 از مسیر VPN عبور نمی‌کند)
- با روشن بودن VPN دیگر، اندروید فقط یک VPN را فعال نگه می‌دارد
- محتوای HTTPS خوانده نمی‌شود، فقط دامنه و پورت
- تشخیص پیش‌زمینه نیاز به دسترسی Usage access دارد
