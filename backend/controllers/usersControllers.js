const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const asyncHandler = require('express-async-handler')
const User = require('../models/usersModel')


const login = asyncHandler( async(req, res) => {
    const { email, password } = req.body
    //verificar si el usuario existe
    const user = await User.findOne({ email })

    if (user && (await bcrypt.compare(password, user.password))) {
        res.status(200).json({
            _id: user.id,
            nombre: user.nombre,
            email: user.email,
            token: generarToken(user._id)
        })
    } else {
        res.status(401)
        throw new Error('Credenciales invalidas')
    }
})

const register = asyncHandler(async(req, res) => {
    const { nombre, email, password } = req.body

    if (!nombre || !email || !password) {
        res.status(400)
        throw new Error('Por favor llena todos los campos')
    }

    //verificar si el usuario ya existe
    const userExiste = await User.findOne({ email })

    if (userExiste) {
        res.status(400)
        throw new Error('El usuario ya existe')
    } else {
        //hash password
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password, salt)
        //crear usuario
        const user = await User.create({
            nombre,
            email,
            password: hashedPassword
        })
        if (user) {
            res.status(201).json({
                _id: user.id,
                nombre: user.nombre,
                email: user.email,
                password: user.password
            })
        } else {
            res.status(400)
            throw new Error('No se pudieron guardar los datos')
    
        }
    }

})

const data = asyncHandler(async(req, res) => {
    res.status(200).json({ message:"data" })
})

//generar token
const generarToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '30d',
    })
}

module.exports = { 
    login,
    register,
    data
}
