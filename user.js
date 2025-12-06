const mongoose = require('mongoose');

// Kullanıcı verisinin yapısını tanımlar
const userSchema = new mongoose.Schema({
  name: {
    type: String, 
    required: true 
  },
  email: {
    type: String,
    required: true,
    unique: true, 
    lowercase: true, 
    trim: true 
  },
  password: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now 
  }
});

// Şemayı kullanarak bir model oluşturur
const User = mongoose.model('User', userSchema);

module.exports = User;