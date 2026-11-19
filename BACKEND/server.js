
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pg from "pg";
import bcrypt from "bcryptjs";
import { randomUUID } from "crypto";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const { Pool } = pg;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 3,
  min: 0,
  connectionTimeoutMillis: 20000,
  idleTimeoutMillis: 10000,
  keepAlive: true,
  application_name: "LiberaCESF"
});

db.on("error", (erro) => {
  console.error("Erro inesperado no banco:", erro);
});

const tabelasPermitidas = [
  "adm",
  "monitor",
  "professor",
  "liberacao"
];

const nomes = [
  "Ana Silva",
  "João Santos",
  "Maria Oliveira",
  "Pedro Costa",
  "Lucas Souza",
  "Julia Ferreira",
  "Gabriel Lima",
  "Beatriz Alves",
  "Rafael Rodrigues",
  "Camila Pereira"
];

const turmas = [
  "1º DS",
  "2º DS",
  "3º DS",
  "1º ADM",
  "2º ADM",
  "3º ADM"
];

function aleatorio(lista) {
  return lista[Math.floor(Math.random() * lista.length)];
}

function validarTabela(tipo) {
  return tabelasPermitidas.includes(tipo);
}

// PÁGINA INICIAL
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ======================================
// CADASTRAR LIBERAÇÃO
// ESTA ROTA PRECISA VIR ANTES DE /:tipo
// ======================================

app.post("/liberacao", async (req, res) => {
  try {
    const {
      nomeProfessor,
      nomeAluno,
      turma,
      data
    } = req.body;

    if (!nomeProfessor || !nomeAluno || !turma || !data) {
      return res.status(400).json({
        erro: "Preencha todos os campos da liberação."
      });
    }

    const resultado = await db.query(
      `INSERT INTO liberacao
       ("nomeProfessor", "nomeAluno", turma, data)
       VALUES ($1, $2, $3, $4::timestamptz)
       RETURNING *`,
      [nomeProfessor, nomeAluno, turma, data]
    );

    res.status(201).json({
      mensagem: "Liberação cadastrada com sucesso!",
      registro: resultado.rows[0]
    });

  } catch (erro) {
    console.error("Erro ao cadastrar liberação:", erro);

    res.status(500).json({
      erro: erro.message
    });
  }
});

// ======================================
// CADASTRAR ADMINISTRADOR, MONITOR E PROFESSOR
// ======================================

app.post("/:tipo", async (req, res) => {
  const { tipo } = req.params;

  if (!["adm", "monitor", "professor"].includes(tipo)) {
    return res.status(400).json({
      erro: "Tabela inválida."
    });
  }

  try {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
      return res.status(400).json({
        erro: "Preencha nome, email e senha."
      });
    }

    const senhaHash = await bcrypt.hash(senha, 10);

    const resultado = await db.query(
      `INSERT INTO ${tipo} (nome, email, senha)
       VALUES ($1, $2, $3)
       RETURNING id, nome, email`,
      [nome, email, senhaHash]
    );

    res.status(201).json(resultado.rows[0]);

  } catch (erro) {
    console.error("Erro ao cadastrar usuário:", erro);

    res.status(500).json({
      erro: erro.message
    });
  }
});

// ======================================
// CONSULTAR TABELAS
// ======================================

app.get("/:tipo", async (req, res) => {
  const { tipo } = req.params;

  if (!validarTabela(tipo)) {
    return res.status(400).json({
      erro: "Tabela inválida."
    });
  }

  try {
    let resultado;

    if (["adm", "monitor", "professor"].includes(tipo)) {
      resultado = await db.query(
        `SELECT id, nome, email
         FROM ${tipo}
         ORDER BY id DESC`
      );
    } else {
      resultado = await db.query(
        `SELECT *
         FROM liberacao
         ORDER BY id DESC`
      );
    }

    res.json(resultado.rows);

  } catch (erro) {
    console.error("Erro ao consultar tabela:", erro);

    res.status(500).json({
      erro: erro.message
    });
  }
});

// ======================================
// GERAR 5 SEEDS ALEATÓRIAS
// ======================================

app.post("/seed/:tipo", async (req, res) => {
  const { tipo } = req.params;

  if (!validarTabela(tipo)) {
    return res.status(400).json({
      erro: "Tabela inválida."
    });
  }

  const client = await db.connect();

  try {
    await client.query("BEGIN");

    const criados = [];

    for (let i = 0; i < 5; i++) {

      if (["adm", "monitor", "professor"].includes(tipo)) {
        const nome = aleatorio(nomes);
        const email = `${tipo}.${randomUUID()}@teste.com`;
        const senha = await bcrypt.hash("123456", 10);

        const resultado = await client.query(
          `INSERT INTO ${tipo} (nome, email, senha)
           VALUES ($1, $2, $3)
           RETURNING id, nome, email`,
          [nome, email, senha]
        );

        criados.push(resultado.rows[0]);

      } else {
        const nomeProfessor = aleatorio(nomes);
        const nomeAluno = aleatorio(nomes);
        const turma = aleatorio(turmas);

        const data = new Date(
          Date.now() +
          Math.floor(Math.random() * 7 * 24 * 60 * 60 * 1000)
        ).toISOString();

        const resultado = await client.query(
          `INSERT INTO liberacao
           ("nomeProfessor", "nomeAluno", turma, data)
           VALUES ($1, $2, $3, $4::timestamptz)
           RETURNING *`,
          [nomeProfessor, nomeAluno, turma, data]
        );

        criados.push(resultado.rows[0]);
      }
    }

    await client.query("COMMIT");

    res.status(201).json({
      mensagem: "5 registros de teste criados!",
      registros: criados
    });

  } catch (erro) {
    await client.query("ROLLBACK");

    console.error("Erro ao gerar seeds:", erro);

    res.status(500).json({
      erro: erro.message
    });

  } finally {
    client.release();
  }
});

// ======================================
// EXCLUIR TODOS OS REGISTROS
// ======================================

app.delete("/:tipo/todos", async (req, res) => {
  const { tipo } = req.params;

  if (!validarTabela(tipo)) {
    return res.status(400).json({
      erro: "Tabela inválida."
    });
  }

  try {
    const resultado = await db.query(
      `DELETE FROM ${tipo}`
    );

    res.json({
      mensagem: "Todos os registros foram excluídos.",
      quantidade: resultado.rowCount
    });

  } catch (erro) {
    console.error("Erro ao excluir todos:", erro);

    res.status(500).json({
      erro: erro.message
    });
  }
});

// ======================================
// EXCLUIR UM REGISTRO
// ======================================

app.delete("/:tipo/:id", async (req, res) => {
  const { tipo, id } = req.params;

  if (!validarTabela(tipo)) {
    return res.status(400).json({
      erro: "Tabela inválida."
    });
  }

  try {
    const resultado = await db.query(
      `DELETE FROM ${tipo}
       WHERE id = $1`,
      [id]
    );

    if (resultado.rowCount === 0) {
      return res.status(404).json({
        erro: "Registro não encontrado."
      });
    }

    res.json({
      mensagem: "Registro excluído com sucesso."
    });

  } catch (erro) {
    console.error("Erro ao excluir registro:", erro);

    res.status(500).json({
      erro: erro.message
    });
  }
});

// ======================================
// INICIAR SERVIDOR
// ======================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
  console.log(`Servidor rodando na porta ${PORT}`);

  try {
    const conexao = await db.connect();

    console.log("Conectado ao Supabase!");

    conexao.release();

  } catch (erro) {
    console.error(
      "Erro ao conectar ao Supabase:",
      erro.message
    );
  }
});
