
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import pg from 'pg';
import bcrypt from 'bcryptjs';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

const { Pool } = pg;

const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    },
    max: 5,
    connectionTimeoutMillis: 15000,
    idleTimeoutMillis: 30000
});

db.on('error', (err) => {
    console.error('Erro inesperado na conexão:', err.message);
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Testar conexão
db.connect()
    .then(client => {
        console.log('Conectado ao PostgreSQL!');
        client.release();
    })
    .catch(error => {
        console.error('Erro no banco:', error.message);
    });

// Rota inicial
app.get('/', (req, res) => {
    res.send('API AUTORIZA CESF funcionando!');
});

// Cadastrar usuário
async function cadastrarUsuario(req, res, tabela) {
    try {
        const { nome, email, senha } = req.body;

        if (!nome || !email || !senha) {
            return res.status(400).json({
                erro: 'Preencha todos os campos.'
            });
        }

        const senhaHash = await bcrypt.hash(senha, 10);

        const resultado = await db.query(
            `INSERT INTO ${tabela} (nome, email, senha)
             VALUES ($1, $2, $3)
             RETURNING id, nome, email`,
            [nome, email, senhaHash]
        );

        res.status(201).json({
            mensagem: 'Usuário cadastrado com sucesso!',
            usuario: resultado.rows[0]
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            erro: 'Erro ao cadastrar usuário.'
        });
    }
}

// Rotas de cadastro
app.post('/adm', (req, res) => {
    cadastrarUsuario(req, res, 'adm');
});

app.post('/monitor', (req, res) => {
    cadastrarUsuario(req, res, 'monitor');
});

app.post('/professor', (req, res) => {
    cadastrarUsuario(req, res, 'professor');
});

// Consultar usuários
async function consultarTabela(req, res, tabela) {
    try {
        const resultado = await db.query(
            `SELECT * FROM ${tabela} ORDER BY id`
        );

        res.json(resultado.rows);

    } catch (error) {
        console.error(error);

        res.status(500).json({
            erro: 'Erro ao consultar registros.'
        });
    }
}

app.get('/adm', (req, res) => {
    consultarTabela(req, res, 'adm');
});

app.get('/monitor', (req, res) => {
    consultarTabela(req, res, 'monitor');
});

app.get('/professor', (req, res) => {
    consultarTabela(req, res, 'professor');
});

// Registrar liberação
app.post('/liberacao', async (req, res) => {
    try {
        const {
            nomeProfessor,
            nomeAluno,
            turma,
            data
        } = req.body;

        if (!nomeProfessor || !nomeAluno || !turma || !data) {
            return res.status(400).json({
                erro: 'Preencha todos os campos.'
            });
        }

        const resultado = await db.query(
            `INSERT INTO liberacao
            ("nomeProfessor", "nomeAluno", turma, data)
            VALUES ($1, $2, $3, $4)
            RETURNING *`,
            [nomeProfessor, nomeAluno, turma, data]
        );

        res.status(201).json({
            mensagem: 'Liberação registrada com sucesso!',
            liberacao: resultado.rows[0]
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            erro: 'Erro ao registrar liberação.'
        });
    }
});

// Consultar liberações
app.get('/liberacao', async (req, res) => {
    try {
        const resultado = await db.query(
            'SELECT * FROM liberacao ORDER BY id DESC'
        );

        res.json(resultado.rows);

    } catch (error) {
        console.error(error);

        res.status(500).json({
            erro: 'Erro ao consultar liberações.'
        });
    }
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
