const express = require('express');
const path = require('path');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 
const nodemailer = require('nodemailer'); // Yeni eklendi
require('dotenv').config(); 

const authMiddleware = require('./auth'); 
const app = express();

// --- E-POSTA AYARI (Nodemailer) ---
const transporter = nodemailer.createTransport({
    service: 'hotmail',
    auth: {
        user: 'pomelita-shop@hotmail.com',
        pass: 'M.stf1655' // Dikkat: Buraya gerçek şifreni yazmalısın
    }
});

let currentOTP = null; // Geçici doğrulama kodu

// --- MONGO VE MODELLER (Aynı kalıyor) ---
mongoose.connect(process.env.MONGO_URI, { dbName: 'PomelitaStore' })
.then(() => { console.log('✅ MongoDB Bağlantısı Başarılı!'); initializeAdminUser(); });

const Kullanici = mongoose.model('Kullanici', new mongoose.Schema({ ad: String, email: { type: String, unique: true }, sifre: String, rol: String }));
const Urun = mongoose.model('Urun', new mongoose.Schema({ title: String, price: String, stok: Number, category: String, desc: String, img: String }), 'urunler');
const Siparis = mongoose.model('Siparis', new mongoose.Schema({ musteri: Object, sepet: Array, toplamTutar: Number, odemeYontemi: String, durum: { type: String, default: 'Yeni Sipariş' }, tarih: String }), 'siparisler'); 
const Mesaj = mongoose.model('Mesaj', new mongoose.Schema({ ad: String, email: String, mesaj: String, tarih: String }), 'mesajlar');
const Ayar = mongoose.model('Ayar', new mongoose.Schema({ tel: String, email: String, address: String, analytics: String, ads: String, insta: String, face: String }), 'ayarlar');
const Kupon = mongoose.model('Kupon', new mongoose.Schema({ kod: String, oran: Number }), 'kuponlar');

async function initializeAdminUser() {
    const adminEmail = "pomelita-shop@hotmail.com"; 
    const adminSifre = "1234"; 
    await Kullanici.deleteMany({ rol: 'admin' });
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(adminSifre, salt);
    await new Kullanici({ ad: "Pomelita Admin", email: adminEmail, sifre: hash, rol: 'admin' }).save();
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// --- 🔐 YENİ GİRİŞ VE DOĞRULAMA ROTASI ---
app.post('/api/giris-iste', async (req, res) => {
    const { email, sifre } = req.body;
    try {
        const user = await Kullanici.findOne({ email });
        if (user && await bcrypt.compare(sifre, user.sifre)) {
            // 6 haneli kod üret
            currentOTP = Math.floor(100000 + Math.random() * 900000).toString();
            
            const mailOptions = {
                from: 'pomelita-shop@hotmail.com',
                to: 'pomelita-shop@hotmail.com', // Kodu kendine gönderiyorsun
                subject: 'Pomelita Admin Giriş Kodu',
                text: `Giriş yapmak için doğrulama kodunuz: ${currentOTP}`
            };

            transporter.sendMail(mailOptions, (err, info) => {
                if (err) return res.status(500).json({ error: 'Mail gönderilemedi' });
                res.json({ message: 'OTP_SENT' });
            });
        } else res.status(401).json({ error: 'Hatalı giriş!' });
    } catch(e) { res.status(500).json({ error: 'Hata' }); }
});

app.post('/api/dogrula', async (req, res) => {
    const { email, code } = req.body;
    if (code === currentOTP) {
        const user = await Kullanici.findOne({ email });
        const token = jwt.sign({ id: user._id, email: user.email, rol: user.rol }, process.env.JWT_SECRET, { expiresIn: '7d' });
        currentOTP = null; // Kodu sıfırla
        res.json({ token, user: { ad: user.ad, rol: user.rol } });
    } else {
        res.status(401).json({ error: 'Hatalı kod!' });
    }
});

// ... Diğer API Rotaları (Aynı kalıyor, ciro filtreleme dahil) ...
app.use('/api', authMiddleware); 
const adminCheck = (req, res, next) => req.user.rol === 'admin' ? next() : res.status(403).json({ error: 'Yetkisiz' });
app.get('/api/dashboard', adminCheck, async (req, res) => {
    const aktifSiparisler = await Siparis.find({ durum: { $ne: 'İptal' } });
    const ciro = aktifSiparisler.reduce((a, b) => a + (parseFloat(String(b.toplamTutar).replace(',','.')) || 0), 0);
    res.json({ toplamCiro: ciro, toplamSiparis: aktifSiparisler.length, toplamUrun: await Urun.countDocuments({}), okunmamisMesaj: await Mesaj.countDocuments({}) });
});
app.get('/api/urunler', async (req, res) => res.json(await Urun.find({})));
app.post('/api/urunler', adminCheck, async (req, res) => { await new Urun(req.body).save(); res.json({ m: 'OK' }); });
app.delete('/api/urunler/:id', adminCheck, async (req, res) => { await Urun.findByIdAndDelete(req.params.id); res.json({ m: 'OK' }); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Sunucu Aktif.`));