const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const LoginSchema = new mongoose.Schema({
  email: { type: String, required: true },
  password: { type: String, required: true },
});

const LoginModel = mongoose.model('Login', LoginSchema);

class Login {
  constructor(body) {
    this.body = body
    this.errors = []
    this.user = null
  }

  async register() {
    this.valida()
    if (this.errors.length > 0) return

    await this.userExists()

    const salt = bcrypt.genSaltSync();
    this.body.password = bcrypt.hashSync(this.body.password, salt);

    try {
      this.user = await LoginModel.create(this.body)
    } catch (e) {
      console.log(e)
    }
  }

  async userExists() {
    const user = await LoginModel.findOne({ email: this.body.email })

    if(user) this.errors.push('Usuário já existe!')
  }

  valida() {
    this.cleanUp()

    //o email precisa ser válido
    if (!validator.isEmail(this.body.email)) this.errors.push('Email inválido')

    //a senha tem que ter entre 4 e 20 caracteres
    if (this.body.password.length < 4 || this.body.password.length > 20) {
      this.errors.push('A senha precisa ter entre 4 e 20 caracteres')
    }
  }

  cleanUp() {
    //Garantir que tds os campos que chegue do formulário sejam string
    for (const key in this.body) {
      if (typeof this.body[key] !== 'string') {
        this.body[key] = ''
      }
    }

    //Garante que o CSRF não vá junto com as outras informações
    this.body = {
      email: this.body.email,
      password: this.body.password
    }
  }

}

module.exports = Login;
