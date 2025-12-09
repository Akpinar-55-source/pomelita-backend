const express = require('express');
const path = require('path');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 
require('dotenv').config(); 

const authMiddleware = require('./auth'); // auth.js artık kök dizinden yükleniyor

const app = express();

// --- 1. VERİ TABANI BAĞLANTISI ---
mongoose.connect(process.env.MONGO_URI, {
    dbName: 'PomelitaStore' 
})
.then(() => {
    console.log('✅ MongoDB Atlas Bağlantısı Başarılı!');
    initializeAdminUser(); 
})
.catch(err => console.error('❌ MongoDB Bağlantı Hatası! Lütfen .env dosyasını kontrol edin. \n Hata Detayı:', err));

// --- 2. VERİ MODELİ TANIMLAMA (SCHEMAS) ---

// Kullanıcı Şeması (Şifre Hashing için pre-save hook ekleniyor)
const KullaniciSchema = new mongoose.Schema({
    ad: String,
    soyad: String,
    email: { type: String, unique: true, required: true },
    sifre: { type: String, required: true }, 
    rol: { type: String, default: 'kullanici' }, 
    kayitTarihi: { type: String, default: () => new Date().toLocaleString('tr-TR') }
});

// 🔥 DÜZELTME: next() çağrıları kaldırıldı (Asenkron hook'lar için doğru kullanım)
KullaniciSchema.pre('save', async function() { 
    if (!this.isModified('sifre')) {
        return; 
    }
    const salt = await bcrypt.genSalt(10);
    this.sifre = await bcrypt.hash(this.sifre, salt);
});

const Kullanici = mongoose.model('Kullanici', KullaniciSchema, 'kullanicilar');

// Diğer Şemalar (Değişmedi)
const UrunSchema = new mongoose.Schema({ title: { type: String, required: true }, price: { type: String, required: true }, stok: { type: Number, default: 0 }, category: { type: String, required: true }, desc: String, img: String });
const Urun = mongoose.model('Urun', UrunSchema, 'urunler');

const SiparisSchema = new mongoose.Schema({ musteri: Object, sepet: Array, toplamTutar: Number, odemeYontemi: String, durum: { type: String, default: 'Yeni Sipariş' }, tarih: String });
const Siparis = mongoose.model('Siparis', SiparisSchema, 'siparisler'); 
const Kupon = mongoose.model('Kupon', new mongoose.Schema({ kod: String, oran: Number }), 'kuponlar');
const Mesaj = mongoose.model('Mesaj', new mongoose.Schema({ ad: String, email: String, mesaj: String, tarih: String }), 'mesajlar');
const Ayar = mongoose.model('Ayar', new mongoose.Schema({ tel: String, email: String, address: String, analytics: String, ads: String, insta: String, face: String }), 'ayarlar');


// Admin Kullanıcısını Başlatma Fonksiyonu 
async function initializeAdminUser() {
    const adminEmail = "admin@pomelita.com"; 
    const existingAdmin = await Kullanici.findOne({ email: adminEmail });
    if (!existingAdmin) {
        console.log("⚙️ Varsayılan admin kullanıcısı oluşturuluyor...");
        const newAdmin = new Kullanici({ 
            ad: "Pomelita", 
            soyad: "Admin", 
            email: adminEmail, 
            sifre: "cokgizliadmin123", 
            rol: 'admin' 
        });
        await newAdmin.save();
        console.log("✅ Varsayılan admin kullanıcısı oluşturuldu.");
        console.log("⚠️ Lütfen şifreyi admin panelinden hemen değiştirin!");
    }
}


// --- 3. EXPRESS ORTAMI ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '.')));

const DOMAIN = 'https://pomelita.com'; 

// --- SAYFALAR ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// --- SEO: OTOMATİK SITEMAP (Değişmedi) ---
app.get('/sitemap.xml', async (req, res) => {
    try {
        const urunler = await Urun.find({}); 
        let xml = `<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>${DOMAIN}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>
            <url><loc>${DOMAIN}/takilar.html</loc><changefreq>daily</changefreq><priority>0.8</priority></url>
            <url><loc>${DOMAIN}/atolye.html</loc><changefreq>monthly</changefreq><priority>0.6</priority></url>`;

        urunler.forEach(u => {
            xml += `
            <url>
                <loc>${DOMAIN}/urun-detay.html?id=${u._id}</loc>
                <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
                <priority>0.8</priority>
            </url>`;
        });

        xml += `</urlset>`;
        res.header('Content-Type', 'application/xml');
        res.send(xml);
    } catch(e) {
        res.status(500).send('Sitemap oluşturma hatası');
    }
});


// --- 🔥 KORUMASIZ (PUBLIC) API ROTLARI ---
app.post('/api/kayit', async (req, res) => {
    const { ad, soyad, email, sifre } = req.body;
    try {
        const yeniUye = new Kullanici({ ad, soyad, email, sifre, rol: 'kullanici' });
        await yeniUye.save();
        
        // Kayıttan hemen sonra Token oluşturup gönderelim
        const token = jwt.sign(
            { id: yeniUye._id, email: yeniUye.email, rol: yeniUye.rol }, 
            process.env.JWT_SECRET, 
            { expiresIn: '7d' } 
        );
        
        const { sifre: hashedPassword, ...safeUser } = yeniUye.toObject(); 

        res.json({ message: 'Kayıt Başarılı', token, user: safeUser });
    } catch(e) { res.status(400).json({ error: e.code === 11000 ? 'Bu e-posta zaten kayıtlı.' : 'Kayıt Hatası.' }); }
});

// GİRİŞ ROTASI (Şifre kontrolü HASH ile yapılıyor ve Token döndürülüyor)
app.post('/api/giris', async (req, res) => {
    const { email, sifre } = req.body;
    try {
        const user = await Kullanici.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Hatalı e-posta veya şifre!' });
        }

        const isMatch = await bcrypt.compare(sifre, user.sifre);
        if (!isMatch) {
            return res.status(401).json({ error: 'Hatalı e-posta veya şifre!' });
        }
        
        const token = jwt.sign(
            { id: user._id, email: user.email, rol: user.rol }, 
            process.env.JWT_SECRET, 
            { expiresIn: '7d' } 
        );

        const { sifre: hashedPassword, ...safeUser } = user.toObject(); 

        res.json({ message: 'Giriş Başarılı', token, user: safeUser });

    } catch(e) { res.status(500).json({ error: 'Sunucu Hatası' }); }
});

// Ürünleri herkese açık listeleme 
app.get('/api/urunler', async (req, res) => {
    try {
        const urunler = await Urun.find({});
        res.json(urunler);
    } catch(e) { res.status(500).json([]); }
});

// Mesaj gönderme (İletişim formu)
app.post('/api/mesajlar', async (req, res) => { 
    try { 
        await new Mesaj({...req.body, tarih: new Date().toLocaleString('tr-TR')}).save(); 
        res.json({message:'OK'}); 
    } catch(e) { res.status(500).json({ error: 'Hata' }); } 
});

// Kuponları herkese açık listeleme (Sadece kontrol için)
app.get('/api/kuponlar', async (req, res) => { 
    try { 
        const kuponlar = await Kupon.find({}).select('kod oran'); 
        res.json(kuponlar); 
    } catch(e) { res.status(500).json([]); } 
});

// Sipariş kaydetme (Ödeme sayfası)
app.post('/api/siparisler', async (req, res) => {
    try {
        const yeniSiparis = new Siparis({...req.body, tarih: new Date().toLocaleString('tr-TR')});
        await yeniSiparis.save();
        res.json({ message: 'Sipariş Alındı' });
    } catch(e) { res.status(500).json({ error: 'Sipariş hatası' }); }
});


// --- 🔥 KORUMALI (AUTH GEREKTİREN) API ROTLARI ---
app.use('/api', authMiddleware); 

// Admin Kontrolü için yardımcı Middleware
const adminCheck = (req, res, next) => {
    if (req.user.rol !== 'admin') {
         return res.status(403).json({ error: 'Yetkiniz yok. Sadece admin erişebilir.' });
    }
    next();
};

// Admin İşlemleri (Sipariş Güncelleme)
app.put('/api/siparisler/:id', adminCheck, async (req, res) => {
    try {
        await Siparis.findByIdAndUpdate(req.params.id, { durum: req.body.durum });
        res.json({message: 'Durum güncellendi'});
    } catch(e) { res.status(404).json({error: 'Sipariş bulunamadı'}); }
});

app.get('/api/dashboard', adminCheck, async (req, res) => {
    try {
        const urunler = await Urun.find({});
        const siparisler = await Siparis.find({});
        const ciro = siparisler.reduce((a,b) => a + (parseFloat(b.toplamTutar)||0), 0);
        res.json({
            toplamCiro: ciro,
            toplamSiparis: siparisler.length,
            toplamUrun: urunler.length,
            okunmamisMesaj: (await Mesaj.countDocuments({})), 
            kritikStok: urunler.filter(x=> x.stok && x.stok < 5).length
        });
    } catch(e) { res.status(500).json({toplamCiro: 0, toplamSiparis: 0, toplamUrun: 0, okunmamisMesaj: 0, kritikStok: 0}); }
});

// ... Diğer tüm admin rotaları (ürün, kupon, mesaj, ayar yönetimi)
app.post('/api/urunler', adminCheck, async (req, res) => {
    try {
        const yeniUrun = new Urun(req.body);
        const kaydedilen = await yeniUrun.save();
        res.json({ message: 'Eklendi', id: kaydedilen._id });
    } catch(e) { res.status(500).json({ error: 'Kaydetme hatası' }); }
});

app.delete('/api/urunler/:id', adminCheck, async (req, res) => {
    try {
        await Urun.findByIdAndDelete(req.params.id);
        res.json({ message: 'Silindi' });
    } catch(e) { res.status(500).json({ error: 'Silme hatası' }); }
});

app.get('/api/siparisler', adminCheck, async (req, res) => {
    try {
        const siparisler = await Siparis.find({}).sort({ tarih: -1 });
        res.json(siparisler);
    } catch(e) { res.status(500).json([]); }
});

app.get('/api/mesajlar', adminCheck, async (req, res) => { 
    try { res.json(await Mesaj.find({})); } catch(e) { res.status(500).json([]); } 
});

app.post('/api/kuponlar', adminCheck, async (req, res) => { 
    try { await new Kupon(req.body).save(); res.json({message:'OK'}); } catch(e) { res.status(500).json({ error: 'Hata' }); } 
});
app.delete('/api/kuponlar/:id', adminCheck, async (req, res) => { 
    try { await Kupon.findByIdAndDelete(req.params.id); res.json({message:'Silindi'}); } catch(e) { res.status(500).json({ error: 'Hata' }); } 
});

app.get('/api/ayarlar', adminCheck, async (req, res) => { 
    try { const ayar = await Ayar.findOne({}); res.json(ayar || {}); } catch(e) { res.status(500).json({}); }
});

app.post('/api/ayarlar', adminCheck, async (req, res) => { 
    try { await Ayar.findOneAndUpdate({}, req.body, { upsert: true, new: true }); res.json({message:'OK'}); } catch(e) { res.status(500).json({ error: 'Hata' }); } 
});


// KULLANICI İŞLEMİ (Token ile siparişleri güvenli çekme)
app.get('/api/siparislerim', async (req, res) => {
    const email = req.user.email; 
    
    try {
        const benimSiparislerim = await Siparis.find({'musteri.email': email}).sort({ tarih: -1 });
        res.json(benimSiparislerim);
    } catch(e) { res.status(500).json([]); }
});


// Sunucuyu Başlat
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("------------------------------------------------");
    console.log(`🚀 SUNUCU ÇALIŞIYOR: http://localhost:${PORT}`);
    console.log("------------------------------------------------");
});