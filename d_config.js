import {config} from 'dotenv'

config()

export const APP_PORT =  process.env.PORT || 5002
export const DB_USER =  process.env.DB_USER || 'sql10684703'
export const DB_PASSWORD =  process.env.DB_PASSWORD ||'bQveMu2qvd'
export const DB_HOST =  process.env.DB_HOST || 'sql10.freemysqlhosting.net'
export const DB_DATABASE =  process.env.DB_DATABASE || 'sql10684703'
export const DB_PORT =  process.env.DB_PORT ||3306

//Datos para el token
export const TOKEN_KEY = "NoLoVasAiM4gIn4RnIeNm1L14ñ05"