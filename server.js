const express = require('express')
const radius = require('radius')
const dgram = require('dgram')
const cors = require('cors')
const morgan = require('morgan')
require("dotenv").config();

const app = express()

const port = process.env.PORT

app.use(cors())
app.use(express.json())
app.use(morgan('dev'))

const RADIUS_SECRET = 'fortigate@11098'
const RADIUS_SERVER = '127.0.0.1'
const RADIUS_PORT = 1812
const NAS_IP = '10.10.10.1'

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body
  console.log(`รับคำขอ login: username=${username}`)

  const packet = radius.encode({
    code: 'Access-Request',
    secret: RADIUS_SECRET,
    identifier: 0,
    attributes: {
      'NAS-IP-Address': NAS_IP,
      'User-Name': username,
      'User-Password': password
    }
  })

  const client = dgram.createSocket('udp4')
  let responded = false

  client.send(packet, 0, packet.length, RADIUS_PORT, RADIUS_SERVER, (err) => {
    if (err) {
      responded = true
      console.error('ส่ง packet ไม่ได้:', err.message)
      client.close()
      return res.status(500).send({ success: false, message: 'ส่ง packet ไม่ได้' })
    } else {
      console.log('ส่ง packet ไปยัง RADIUS เรียบร้อย')
    }
  })

  client.on('message', (msg) => {
    if (responded) return
    responded = true

    const response = radius.decode({ packet: msg, secret: RADIUS_SECRET })
    const success = response.code === 'Access-Accept'
    console.log(`ได้ response จาก RADIUS: ${response.code}`)

    client.close()
    res.send({ success, message: success ? 'เข้าสำเร็จ' : 'เข้าสำหรับไม่ได้' })
  })

  client.on('error', (err) => {
    if (responded) return
    responded = true

    console.error('เกิด error ที่ client:', err)
    client.close()
    res.status(500).send({ success: false, message: 'เกิดข้อผิดพลาดที่ client' })
  })

  setTimeout(() => {
    if (responded) return
    responded = true

    console.warn('Timeout: RADIUS ไม่ตอบกลับภายใน 1.5 วินาที')
    client.close()
    res.status(504).send({ success: false, message: 'Timeout: ไม่มีการตอบกลับจาก RADIUS' })
  }, 1500)
})

app.listen(port, () => {
  console.log(`API Server ready: http://localhost:${port}`)
})
