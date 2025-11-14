const jwt = require('jsonwebtoken')
const User = require('../models/usersModel')

const protect = async (req, res, next) => {

    let token

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            //obtener token del encabezado de autorizacion
            token = req.headers.authorization.split(' ')[1]
            //verificar token
            const decoded = jwt.verify(token, process.env.JWT_SECRET)
            //obtener usuario del token
            req.user = await User.findById(decoded.id).select('-password')

            next()
        } catch (error) {
            console.log(error)
            res.status(401)
            throw new Error('No autorizado')
        }
    
    }
    if (!token) {
        res.status(401)
        throw new Error('No autorizado, no hay token')
    }
}
module.exports = { protect }
