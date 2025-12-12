const express = require('express');
const path = require('path');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 
require('dotenv').config(); 

const authMiddleware = require('./auth'); // auth.js kök dizinde olmalı

const app = express();

// --- 1. VERİ TABANI BAĞLANTISI ---
mongoose.connect(process.env.MONGO_URI, {
    dbName: 'PomelitaStore' 
})
.then(() => {
    console.log('✅ MongoDB Atlas Bağlantısı Başarılı!');
    initializeAdminUser(); 
})
.catch(err => console.error('❌ MongoDB Bağlantı Hatası!', err));

// --- 2. VERİ MODELLERİ ---

const KullaniciSchema = new mongoose.Schema({
    ad: String,
    soyad: String,
    email: { type: String, unique: true, required: true },
    sifre: { type: String, required: true }, 
    rol: { type: String, default: 'kullanici' }, 
    kayitTarihi: { type: String, default: () => new Date().toLocaleString('tr-TR') }
});

KullaniciSchema.pre('save', async function() { 
    if (!this.isModified('sifre')) return; 
    const salt = await bcrypt.genSalt(10);
    this.sifre = await bcrypt.hash(this.sifre, salt);
});

const Kullanici = mongoose.model('Kullanici', KullaniciSchema, 'kullanicilar');
const Urun = mongoose.model('Urun', new mongoose.Schema({ title: String, price: String, stok: Number, category: String, desc: String, img: String }), 'urunler');
const Siparis = mongoose.model('Siparis', new mongoose.Schema({ musteri: Object, sepet: Array, toplamTutar: Number, odemeYontemi: String, durum: { type: String, default: 'Yeni Sipariş' }, tarih: String }), 'siparisler'); 
const Kupon = mongoose.model('Kupon', new mongoose.Schema({ kod: String, oran: Number }), 'kuponlar');
const Mesaj = mongoose.model('Mesaj', new mongoose.Schema({ ad: String, email: String, mesaj: String, tarih: String }), 'mesajlar');
const Ayar = mongoose.model('Ayar', new mongoose.Schema({ tel: String, email: String, address: String, analytics: String, ads: String, insta: String, face: String }), 'ayarlar');

async function initializeAdminUser() {
    const adminEmail = "admin@pomelita.com"; 
    const existingAdmin = await Kullanici.findOne({ email: adminEmail });
    if (!existingAdmin) {
        const newAdmin = new Kullanici({ ad: "Pomelita", soyad: "Admin", email: adminEmail, sifre: "cokgizliadmin123", rol: 'admin' });
        await newAdmin.save();
    }
}

// --- 3. MIDDLEWARE & STATIC ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '.')));

const DOMAIN = 'https://pomelita.onrender.com';

// --- SAYFALAR ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// --- PUBLIC API ---
app.post('/api/giris', async (req, res) => {
    const { email, sifre } = req.body;
    try {
        const user = await Kullanici.findOne({ email });
        if (!user || !(await bcrypt.compare(sifre, user.sifre))) {
            return res.status(401).json({ error: 'Hatalı e-posta veya şifre!' });
        }
        const token = jwt.sign({ id: user._id, email: user.email, rol: user.rol }, process.env.JWT_SECRET, { expiresIn: '7d' });
        const { sifre: pass, ...safeUser } = user.toObject(); 
        res.json({ token, user: safeUser });
    } catch(e) { res.status(500).json({ error: 'Sunucu Hatası' }); }
});

app.get('/api/urunler', async (req, res) => {
    try { res.json(await Urun.find({})); } catch(e) { res.status(500).json([]); }
});

app.post('/api/siparisler', async (req, res) => {
    try {
        const yeni = new Siparis({...req.body, tarih: new Date().toLocaleString('tr-TR')});
        await yeni.save();
        res.json({ message: 'OK' });
    } catch(e) { res.status(500).json({ error: 'Hata' }); }
});

// --- 🔥 ADMIN API (GÜVENLİ VE FİLTRELİ) ---
app.use('/api', authMiddleware); 

const adminCheck = (req, res, next) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    next();
};

// 1. DASHBOARD: İPTAL EDİLENLER CİRODAN VE SAYIDAN DÜŞÜLÜR
app.get('/api/dashboard', adminCheck, async (req, res) => {
    try {
        const urunler = await Urun.find({});
        // Sadece durumu 'İptal' olmayanları getir
        const aktifSiparisler = await Siparis.find({ durum: { $ne: 'İptal' } });
        
        const ciro = aktifSiparisler.reduce((a, b) => {
            let amount = 0;
            if (b.toplamTutar) {
                const priceString = String(b.toplamTutar).replace(',', '.');
                amount = parseFloat(priceString);
            }
            return a + (amount || 0);
        }, 0);
        
        res.json({
            toplamCiro: ciro,
            toplamSiparis: aktifSiparisler.length,
            toplamUrun: urunler.length,
            okunmamisMesaj: (await Mesaj.countDocuments({})), 
            kritikStok: urunler.filter(x => x.stok < 5).length
        });
    } catch(e) { res.status(500).json({ toplamCiro: 0 }); }
});

// 2. SİPARİŞ LİSTESİ: İPTAL EDİLENLER LİSTEDEN SİLİNİR (GİZLENİR)
app.get('/api/siparisler', adminCheck, async (req, res) => {
    try {
        // Durumu 'İptal' olmayanları tarihe göre sırala
        const siparisler = await Siparis.find({ durum: { $ne: 'İptal' } }).sort({ tarih: -1 });
        res.json(siparisler);
    } catch(e) { res.status(500).json([]); }
});

app.put('/api/siparisler/:id', adminCheck, async (req, res) => {
    try {
        await Siparis.findByIdAndUpdate(req.params.id, { durum: req.body.durum });
        res.json({ message: 'Güncellendi' });
    } catch(e) { res.status(404).json({ error: 'Hata' }); }
});

// DİĞER ADMIN İŞLEMLERİ
app.post('/api/urunler', adminCheck, async (req, res) => {
    try { const yeni = new Urun(req.body); await yeni.save(); res.json({ message: 'Eklendi' }); } catch(e) { res.status(500).json({ error: 'Hata' }); }
});

app.delete('/api/urunler/:id', adminCheck, async (req, res) => {
    try { await Urun.findByIdAndDelete(req.params.id); res.json({ message: 'Silindi' }); } catch(e) { res.status(500).json({ error: 'Hata' }); }
});

app.get('/api/mesajlar', adminCheck, async (req, res) => { 
    try { res.json(await Mesaj.find({})); } catch(e) { res.status(500).json([]); } 
});

app.get('/api/ayarlar', adminCheck, async (req, res) => { 
    try { res.json(await Ayar.findOne({}) || {}); } catch(e) { res.status(500).json({}); }
});

app.post('/api/ayarlar', adminCheck, async (req, res) => { 
    try { await Ayar.findOneAndUpdate({}, req.body, { upsert: true }); res.json({ message: 'Kaydedildi' }); } catch(e) { res.status(500).json({ error: 'Hata' }); } 
});

// BAŞLAT
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Sunucu Yayında: Port ${PORT}`));