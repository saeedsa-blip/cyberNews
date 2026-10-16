# رادار التهديدات السيبرانية

نشرة يومية لأبرز الأحداث السيبرانية المحلية والإقليمية والعالمية، مع مؤشرات من AlienVault OTX.

## الملفات
- `index.html` : صفحة الموقع
- `config.json` : المصادر (RSS) وكلمات الفرز (محلي / إقليمي / عالمي) والخطورة
- `data/trends.json` : جدول تقييم الاتجاهات، **يُعدَّل يدوياً**
- `data/exclude.json` : قائمة استبعاد الأخبار (روابط أو كلمات)، **تُعدَّل يدوياً**
- `data/news.json` و `data/intel.json` : تتعبّى تلقائياً، لا تعدّلها
- `scripts/collect.py` : يجمع الأخبار والمؤشرات
- `.github/workflows/update.yml` : يشغّل السكربت كل يوم 7:00 صباحاً بتوقيت الإمارات
- `netlify/functions/latest.mjs` : يخدم زر «تحديث البيانات»

## الإعداد (مرة وحدة)
1. في مستودع GitHub: افتح Settings ثم Secrets and variables ثم Actions، وأضف سراً جديداً باسم `OTX_API_KEY` وحط فيه مفتاح OTX.
2. في Netlify: اختر Add new site ثم Import from GitHub، واختر المستودع `cyber-radar`. اترك أمر البناء فاضي.
3. في GitHub: افتح تبويب Actions، واختر Update data، واضغط Run workflow عشان تتعبّى البيانات أول مرة.

## إضافة مصدر جديد
أضف سطر في `feeds` داخل `config.json` فيه الاسم ورابط RSS ورابط الموقع.
