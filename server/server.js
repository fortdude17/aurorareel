require('dotenv').config()
const express = require('express')
const app = express()

app.use(express.json())
app.use(express.static('public'))

app.get('/api/health', (_,res)=>res.json({ok:true}))

app.listen(3000,()=>console.log('AuroraReel running http://localhost:3000'))
