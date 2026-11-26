
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const { Pool } = pg;
const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL não configurada no .env");
}

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error("Configure uma JWT_SECRET com pelo menos 32 caracteres.");
}

// ======================================
// CONFIGURAÇÕES
// ======================================

const origensPermitidas = [
    process.env.FRONTEND_URL,
    "http://localhost:3000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5173"
].filter(Boolean);

app.use(cors({
    origin(origem, callback) {
        if (!origem || origensPermitidas.includes(origem)) {
            return callback(null, true);
        }

        return callback(new Error("Origem não permitida pelo CORS."));
    }
}));

app.use(express.json({ limit: "1mb" }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    },
    connectionTimeoutMillis: 15000,
    idleTimeoutMillis: 30000,
    max: 10
});

const DESTINOS_VALIDOS = [
    "Banheiro",
    "Biblioteca",
    "Setor Pedagogico",
    "Outro"
];

const PERFIS = {
    ADMINISTRADOR: "ADIMINISTRAÇÃO",
    ADMINISTRACAO: "ADIMINISTRAÇÃO",
    FUNCIONARIO: "INSPETOR",
    INSPETOR: "INSPETOR",
    PROFESSOR: "PROFESSOR"
};

// ======================================
// FUNÇÕES AUXILIARES
// ======================================

function normalizarTexto(valor) {
    return String(valor || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .trim()
        .toUpperCase();
}

function normalizarPerfil(perfil) {
    return PERFIS[normalizarTexto(perfil)] || null;
}

function gerarToken(usuario) {
    return jwt.sign(
        {
            id: usuario.id,
            nome: usuario.nome,
            email: usuario.email,
            perfil: usuario.perfil
        },
        JWT_SECRET,
        {
            expiresIn: "8h"
        }
    );
}

function autenticar(req, res, next) {
    const cabecalho = req.headers.authorization;

    if (!cabecalho || !cabecalho.startsWith("Bearer ")) {
        return res.status(401).json({
            erro: "Token não informado."
        });
    }

    const token = cabecalho.split(" ")[1];

    try {
        req.usuario = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({
            erro: "Token inválido ou expirado."
        });
    }
}

function permitirPerfis(...perfis) {
    return (req, res, next) => {
        if (!perfis.includes(req.usuario.perfil)) {
            return res.status(403).json({
                erro: "Você não possui permissão para acessar esta função."
            });
        }

        next();
    };
}

function erroBanco(res, erro) {
    console.error("Erro no banco:", erro.message);

    if (erro.code === "23503") {
        return res.status(400).json({
            erro: "Registro relacionado não encontrado."
        });
    }

    if (erro.code === "23505") {
        return res.status(409).json({
            erro: "Este registro já existe."
        });
    }

    if (erro.code === "23514") {
        return res.status(400).json({
            erro: "Os dados não respeitam as regras do banco."
        });
    }

    return res.status(500).json({
        erro: "Erro interno no servidor."
    });
}

// ======================================
// ROTAS PÚBLICAS
// ======================================

app.get("/", (req, res) => {
    res.json({
        mensagem: "API LiberaCESF funcionando!",
        status: "online"
    });
});

app.get("/api/status", async (req, res) => {
    try {
        await pool.query("SELECT NOW()");

        res.json({
            servidor: "online",
            banco: "conectado"
        });
    } catch (erro) {
        console.error(erro.message);

        res.status(503).json({
            servidor: "online",
            banco: "desconectado"
        });
    }
});

// ======================================
// LOGIN
// ======================================

app.post("/api/login", async (req, res) => {
    try {
        const { email, senha, perfil } = req.body;

        if (!email || !senha) {
            return res.status(400).json({
                erro: "Informe o e-mail e a senha."
            });
        }

        const resultado = await pool.query(
            `SELECT id, nome, email, senha, perfil
             FROM usuarios
             WHERE LOWER(email) = LOWER($1)`,
            [String(email).trim()]
        );

        if (resultado.rows.length === 0) {
            return res.status(401).json({
                erro: "E-mail ou senha incorretos."
            });
        }

        const usuario = resultado.rows[0];

        const senhaCorreta = await bcrypt.compare(
            senha,
            usuario.senha
        );

        if (!senhaCorreta) {
            return res.status(401).json({
                erro: "E-mail ou senha incorretos."
            });
        }

        if (perfil) {
            const perfilSolicitado = normalizarPerfil(perfil);

            if (!perfilSolicitado || perfilSolicitado !== usuario.perfil) {
                return res.status(403).json({
                    erro: "Este usuário não pertence ao perfil selecionado."
                });
            }
        }

        const token = gerarToken(usuario);

        res.json({
            mensagem: "Login realizado com sucesso.",
            token,
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email,
                perfil: usuario.perfil
            }
        });

    } catch (erro) {
        erroBanco(res, erro);
    }
});

// ======================================
// USUÁRIOS
// ======================================

app.get(
    "/api/usuarios",
    autenticar,
    permitirPerfis("ADIMINISTRAÇÃO"),
    async (req, res) => {
        try {
            const resultado = await pool.query(
                `SELECT id, nome, email, perfil
                 FROM usuarios
                 ORDER BY nome`
            );

            res.json(resultado.rows);
        } catch (erro) {
            erroBanco(res, erro);
        }
    }
);

// ======================================
// TURMAS
// ======================================

app.get("/api/turmas", autenticar, async (req, res) => {
    try {
        const resultado = await pool.query(
            `SELECT id, nome
             FROM turmas
             ORDER BY nome`
        );

        res.json(resultado.rows);
    } catch (erro) {
        erroBanco(res, erro);
    }
});

// ======================================
// ALUNOS
// ======================================

app.get("/api/alunos", autenticar, async (req, res) => {
    try {
        const busca = String(req.query.busca || "").trim();
        const turmaId = req.query.turma_id;

        const resultado = await pool.query(
            `SELECT
                a.id,
                a.nome,
                a.matricula,
                a.turma_id,
                t.nome AS turma
             FROM alunos a
             INNER JOIN turmas t ON t.id = a.turma_id
             WHERE (
                $1 = ''
                OR a.nome ILIKE '%' || $1 || '%'
                OR a.matricula ILIKE '%' || $1 || '%'
             )
             AND (
                $2::INTEGER IS NULL
                OR a.turma_id = $2
             )
             ORDER BY a.nome
             LIMIT 100`,
            [
                busca,
                turmaId ? Number(turmaId) : null
            ]
        );

        res.json(resultado.rows);
    } catch (erro) {
        erroBanco(res, erro);
    }
});

// ======================================
// CRIAR AUTORIZAÇÃO
// ======================================

app.post(
    "/api/autorizacoes",
    autenticar,
    permitirPerfis("PROFESSOR"),
    async (req, res) => {
        try {
            const { aluno_id, destino } = req.body;

            const alunoId = Number(aluno_id);

            if (!Number.isInteger(alunoId) || alunoId <= 0) {
                return res.status(400).json({
                    erro: "Informe um aluno válido."
                });
            }

            if (!DESTINOS_VALIDOS.includes(destino)) {
                return res.status(400).json({
                    erro: "Destino inválido."
                });
            }

            const resultado = await pool.query(
                `INSERT INTO autorizacoes
                    (aluno_id, professor_id, destino, status)
                 VALUES ($1, $2, $3, 'ATIVA')
                 RETURNING *`,
                [
                    alunoId,
                    req.usuario.id,
                    destino
                ]
            );

            res.status(201).json({
                mensagem: "Autorização criada com sucesso.",
                autorizacao: resultado.rows[0]
            });

        } catch (erro) {
            erroBanco(res, erro);
        }
    }
);

// ======================================
// LISTAR AUTORIZAÇÕES
// ======================================

app.get(
    "/api/autorizacoes",
    autenticar,
    async (req, res) => {
        try {
            const { status, turma_id } = req.query;

            const resultado = await pool.query(
                `SELECT
                    au.id,
                    au.aluno_id,
                    au.professor_id,
                    au.destino,
                    au.horario_saida,
                    au.horario_retorno,
                    au.status,
                    al.nome AS aluno,
                    al.matricula,
                    t.nome AS turma,
                    u.nome AS professor
                 FROM autorizacoes au
                 INNER JOIN alunos al ON al.id = au.aluno_id
                 INNER JOIN turmas t ON t.id = al.turma_id
                 INNER JOIN usuarios u ON u.id = au.professor_id
                 WHERE
                    ($1::VARCHAR IS NULL OR au.status = $1)
                    AND
                    ($2::INTEGER IS NULL OR al.turma_id = $2)
                    AND
                    (
                        $3::INTEGER IS NULL
                        OR au.professor_id = $3
                    )
                 ORDER BY au.horario_saida DESC`,
                [
                    status || null,
                    turma_id ? Number(turma_id) : null,
                    req.usuario.perfil === "PROFESSOR"
                        ? req.usuario.id
                        : null
                ]
            );

            res.json(resultado.rows);

        } catch (erro) {
            erroBanco(res, erro);
        }
    }
);

// ======================================
// CONSULTAR UMA AUTORIZAÇÃO
// ======================================

app.get(
    "/api/autorizacoes/:id",
    autenticar,
    async (req, res) => {
        try {
            const id = Number(req.params.id);

            if (!Number.isInteger(id) || id <= 0) {
                return res.status(400).json({
                    erro: "ID inválido."
                });
            }

            const resultado = await pool.query(
                `SELECT
                    au.*,
                    al.nome AS aluno,
                    al.matricula,
                    t.nome AS turma,
                    u.nome AS professor
                 FROM autorizacoes au
                 INNER JOIN alunos al ON al.id = au.aluno_id
                 INNER JOIN turmas t ON t.id = al.turma_id
                 INNER JOIN usuarios u ON u.id = au.professor_id
                 WHERE au.id = $1`,
                [id]
            );

            if (resultado.rows.length === 0) {
                return res.status(404).json({
                    erro: "Autorização não encontrada."
                });
            }

            const autorizacao = resultado.rows[0];

            if (
                req.usuario.perfil === "PROFESSOR" &&
                autorizacao.professor_id !== req.usuario.id
            ) {
                return res.status(403).json({
                    erro: "Você não pode consultar esta autorização."
                });
            }

            res.json(autorizacao);

        } catch (erro) {
            erroBanco(res, erro);
        }
    }
);

// ======================================
// CONCLUIR AUTORIZAÇÃO
// ======================================

app.patch(
    "/api/autorizacoes/:id/retorno",
    autenticar,
    permitirPerfis(
        "INSPETOR",
        "ADIMINISTRAÇÃO",
        "PROFESSOR"
    ),
    async (req, res) => {
        try {
            const id = Number(req.params.id);

            if (!Number.isInteger(id) || id <= 0) {
                return res.status(400).json({
                    erro: "ID inválido."
                });
            }

            const resultado = await pool.query(
                `UPDATE autorizacoes
                 SET horario_retorno = CURRENT_TIMESTAMP,
                     status = 'CONCLUIDA'
                 WHERE id = $1
                   AND status = 'ATIVA'
                   AND (
                        $2::INTEGER IS NULL
                        OR professor_id = $2
                   )
                 RETURNING *`,
                [
                    id,
                    req.usuario.perfil === "PROFESSOR"
                        ? req.usuario.id
                        : null
                ]
            );

            if (resultado.rowCount === 0) {
                return res.status(404).json({
                    erro: "Autorização não encontrada, já concluída ou sem permissão."
                });
            }

            res.json({
                mensagem: "Autorização concluída com sucesso.",
                autorizacao: resultado.rows[0]
            });

        } catch (erro) {
            erroBanco(res, erro);
        }
    }
);

// ======================================
// RELATÓRIOS
// ======================================

app.get(
    "/api/relatorios",
    autenticar,
    permitirPerfis("INSPETOR", "ADIMINISTRAÇÃO"),
    async (req, res) => {
        try {
            const resumo = await pool.query(
                `SELECT
                    COUNT(*)::INTEGER AS total,
                    COUNT(*) FILTER (WHERE status = 'ATIVA')::INTEGER AS ativas,
                    COUNT(*) FILTER (WHERE status = 'CONCLUIDA')::INTEGER AS concluidas,
                    COUNT(*) FILTER (WHERE status = 'EXPIRADA')::INTEGER AS expiradas
                 FROM autorizacoes`
            );

            const destinos = await pool.query(
                `SELECT
                    destino,
                    COUNT(*)::INTEGER AS quantidade
                 FROM autorizacoes
                 GROUP BY destino
                 ORDER BY quantidade DESC`
            );

            const porTurma = await pool.query(
                `SELECT
                    t.nome AS turma,
                    COUNT(au.id)::INTEGER AS quantidade
                 FROM turmas t
                 LEFT JOIN alunos al ON al.turma_id = t.id
                 LEFT JOIN autorizacoes au ON au.aluno_id = al.id
                 GROUP BY t.id, t.nome
                 ORDER BY t.nome`
            );

            res.json({
                resumo: resumo.rows[0],
                destinos: destinos.rows,
                turmas: porTurma.rows
            });

        } catch (erro) {
            erroBanco(res, erro);
        }
    }
);

// ======================================
// RECUPERAÇÃO DE SENHA
// ======================================

app.post("/api/recuperar-senha", (req, res) => {
    res.status(501).json({
        erro: "Recuperação de senha ainda não configurada.",
        mensagem: "Esta funcionalidade precisa de integração com um serviço de e-mail."
    });
});

// ======================================
// TRATAMENTO DE ERROS
// ======================================

app.use((req, res) => {
    res.status(404).json({
        erro: "Rota não encontrada."
    });
});

app.use((erro, req, res, next) => {
    console.error("Erro:", erro.message);

    if (erro.message === "Origem não permitida pelo CORS.") {
        return res.status(403).json({
            erro: erro.message
        });
    }

    res.status(500).json({
        erro: "Erro interno no servidor."
    });
});

// ======================================
// INICIAR SERVIDOR
// ======================================

async function iniciarServidor() {
    try {
        await pool.query("SELECT NOW()");
        console.log("Supabase conectado com sucesso!");

        app.listen(PORT, () => {
            console.log(`LiberaCESF rodando na porta ${PORT}`);
        });
    } catch (erro) {
        console.error("Não foi possível conectar ao Supabase:");
        console.error(erro.message);
        process.exit(1);
    }
}

iniciarServidor();
