const mysql = require('mysql2');
require('dotenv').config();

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME_BACKOFFICE,
    connectionLimit: 10, // จำกัดจำนวนการเชื่อมต่อสูงสุด
    waitForConnections: true, // รอการเชื่อมต่อถ้ามีการใช้งานเกิน limit
    queueLimit: 0, // ไม่จำกัดคิว (0 = ไม่จำกัด)
    idleTimeout: 60000 // ปิดการเชื่อมต่อที่ไม่ได้ใช้งานหลังจาก 60 วินาที (หน่วยเป็นมิลลิวินาที)
});

module.exports = pool.promise();