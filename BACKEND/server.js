
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
const { Pool } = pg;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// CONEXÃO COM SUPABASE
// ==========================================

if (!process.env.DATABASE_URL) {
    console.error("ERRO: DATABASE_URL não configurada.");
    process.exit(1);
}

if (!process.env.JWT_SECRET) {
    console.error("ERRO: JWT_SECRET não configurada.");
    process.exit(1);
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    },
    connectionTimeoutMillis: 15000,
    idleTimeoutMillis: 30000,
    max: 10
});

pool.on("error", (err) => {
    console.error("Erro inesperado no PostgreSQL:", err.message);
});

async function consultar(sql, valores = []) {
    return pool.query(sql, valores);
}

// ==========================================
// PERFIS
// ==========================================

const PERFIS = {
    ADMINISTRADOR: "ADIMINISTRAÇÃO",
    FUNCIONARIO: "INSPETOR",
    PROFESSOR: "PROFESSOR"
};

function perfilValido(perfil) {
    return Object.values(PERFIS).includes(perfil);
}

// ==========================================
// AUTENTICAÇÃO
// ==========================================

function gerarToken(usuario) {
    return jwt.sign(
        {
            id: usuario.id,
            nome: usuario.nome,
            email: usuario.email,
            perfil: usuario.perfil
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "8h"
        }
    );
}

function autenticar(req, res, next) {
    const autorizacao = req.headers.authorization;

    if (!autorizacao || !autorizacao.startsWith("Bearer ")) {
        return res.status(401).json({
            erro: "Token não informado."
        });
    }

    const token = autorizacao.split(" ")[1];

    try {
        req.usuario = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({
            erro: "Token inválido ou expirado."
        });
    }
}

function permitir(...perfis) {
    return (req, res, next) => {
        if (!req.usuario || !perfis.includes(req.usuario.perfil)) {
            return res.status(403).json({
                erro: "Você não tem permissão para realizar esta operação."
            });
        }

        next();
    };
}

const ADMIN = PERFIS.ADMINISTRADOR;
const INSPETOR = PERFIS.FUNCIONARIO;
const PROFESSOR = PERFIS.PROFESSOR;

// ==========================================
// ROTA INICIAL
// ==========================================

app.get("/", (req, res) => {
    res.json({
        sistema: "AUTORIZA CESF",
        mensagem: "API funcionando!",
        banco: "Supabase PostgreSQL",
        versao: "1.0.0"
    });
});

// ==========================================
// VERIFICAR CONEXÃO
// ==========================================

app.get("/api/status", async (req, res) => {
    try {
        const resultado = await consultar(
            "SELECT NOW() AS horario"
        );

        res.json({
            conectado: true,
            banco: "Supabase",
            horario: resultado.rows[0].horario
        });
    } catch (erro) {
        console.error(erro);

        res.status(500).json({
            conectado: false,
            erro: "Não foi possível conectar ao banco."
        });
    }
});

// ==========================================
// LOGIN
// ==========================================

app.post("/api/login", async (req, res) => {
    try {
        const { email, senha, perfil } = req.body;

        if (!email || !senha) {
            return res.status(400).json({
                erro: "Informe o e-mail e a senha."
            });
        }

        const resultado = await consultar(
            `SELECT id, nome, email, senha, perfil
             FROM usuarios
             WHERE LOWER(email) = LOWER($1)`,
            [email.trim()]
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

        // Verifica se o perfil escolhido na tela
        // corresponde ao perfil cadastrado.

        if (perfil) {
            const perfilEscolhido = PERFIS[perfil.toUpperCase()];

            if (!perfilEscolhido || perfilEscolhido !== usuario.perfil) {
                return res.status(403).json({
                    erro: "Este usuário não pertence ao perfil selecionado."
                });
            }
        }

        const token = gerarToken(usuario);

        res.json({
            sucesso: true,
            mensagem: "Login realizado com sucesso!",
            token,
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email,
                perfil: usuario.perfil
            }
        });

    } catch (erro) {
        console.error("Erro no login:", erro);

        res.status(500).json({
            erro: "Erro ao realizar login."
        });
    }
});

// ==========================================
// CONSULTAR USUÁRIOS
// ==========================================

app.get(
    "/api/usuarios",
    autenticar,
    permitir(ADMIN),
    async (req, res) => {
        try {
            const resultado = await consultar(
                `SELECT id, nome, email, perfil
                 FROM usuarios
                 ORDER BY nome`
            );

            res.json(resultado.rows);

        } catch (erro) {
            console.error(erro);

            res.status(500).json({
                erro: "Erro ao consultar usuários."
            });
        }
    }
);

// ==========================================
// LISTAR TURMAS
// ==========================================

app.get(
    "/api/turmas",
    autenticar,
    async (req, res) => {
        try {
            const resultado = await consultar(
                `SELECT id, nome
                 FROM turmas
                 ORDER BY nome`
            );

            res.json(resultado.rows);

        } catch (erro) {
            console.error(erro);

            res.status(500).json({
                erro: "Erro ao consultar turmas."
            });
        }
    }
);

// ==========================================
// PESQUISAR ALUNOS
// ==========================================

app.get(
    "/api/alunos",
    autenticar,
    async (req, res) => {
        try {
            const busca = (req.query.busca || "").trim();
            const turmaId = req.query.turma_id;

            const valores = [];
            let condicoes = [];

            if (busca) {
                valores.push(`%${busca}%`);

                condicoes.push(
                    `(a.nome ILIKE $${valores.length}
                     OR a.matricula ILIKE $${valores.length})`
                );
            }

            if (turmaId) {
                valores.push(turmaId);

                condicoes.push(
                    `a.turma_id = $${valores.length}`
                );
            }

            const where = condicoes.length
                ? `WHERE ${condicoes.join(" AND ")}`
                : "";

            const resultado = await consultar(
                `SELECT
                    a.id,
                    a.nome,
                    a.matricula,
                    t.id AS turma_id,
                    t.nome AS turma
                 FROM alunos a
                 INNER JOIN turmas t
                    ON t.id = a.turma_id
                 ${where}
                 ORDER BY a.nome
                 LIMIT 100`,
                valores
            );

            res.json(resultado.rows);

        } catch (erro) {
            console.error(erro);

            res.status(500).json({
                erro: "Erro ao pesquisar alunos."
            });
        }
    }
);

// ==========================================
// CRIAR AUTORIZAÇÃO
// ==========================================

app.post(
    "/api/autorizacoes",
    autenticar,
    permitir(PROFESSOR),
    async (req, res) => {
        try {
            const {
                aluno_id,
                destino,
                horario_saida
            } = req.body;

            if (!aluno_id || !destino) {
                return res.status(400).json({
                    erro: "Informe o aluno e o destino."
                });
            }

            const destinosPermitidos = [
                "Banheiro",
                "Biblioteca",
                "Setor Pedagogico",
                "Outro"
            ];

            if (!destinosPermitidos.includes(destino)) {
                return res.status(400).json({
                    erro: "Destino inválido."
                });
            }

            // Confere se o aluno existe.

            const aluno = await consultar(
                "SELECT id FROM alunos WHERE id = $1",
                [aluno_id]
            );

            if (aluno.rows.length === 0) {
                return res.status(404).json({
                    erro: "Aluno não encontrado."
                });
            }

            // O professor vem do token autenticado.
            // Não aceitamos professor_id enviado pelo frontend.

            const professor = await consultar(
                `SELECT id
                 FROM usuarios
                 WHERE id = $1 AND perfil = $2`,
                [req.usuario.id, PROFESSOR]
            );

            if (professor.rows.length === 0) {
                return res.status(403).json({
                    erro: "Professor não encontrado."
                });
            }

            let resultado;

            if (horario_saida) {
                const data = new Date(horario_saida);

                if (Number.isNaN(data.getTime())) {
                    return res.status(400).json({
                        erro: "Data e horário inválidos."
                    });
                }

                resultado = await consultar(
                    `INSERT INTO autorizacoes
                        (aluno_id, professor_id, destino, horario_saida)
                     VALUES ($1, $2, $3, $4)
                     RETURNING *`,
                    [
                        aluno_id,
                        req.usuario.id,
                        destino,
                        horario_saida
                    ]
                );
            } else {
                resultado = await consultar(
                    `INSERT INTO autorizacoes
                        (aluno_id, professor_id, destino)
                     VALUES ($1, $2, $3)
                     RETURNING *`,
                    [
                        aluno_id,
                        req.usuario.id,
                        destino
                    ]
                );
            }

            res.status(201).json({
                sucesso: true,
                mensagem: "Autorização emitida com sucesso!",
                autorizacao: resultado.rows[0]
            });

        } catch (erro) {
            console.error("Erro ao criar autorização:", erro);

            res.status(500).json({
                erro: "Não foi possível criar a autorização."
            });
        }
    }
);

// ==========================================
// LISTAR AUTORIZAÇÕES
// ==========================================

app.get(
    "/api/autorizacoes",
    autenticar,
    async (req, res) => {
        try {
            const {
                busca,
                status,
                data_inicio,
                data_fim
            } = req.query;

            const valores = [];
            const condicoes = [];

            // Professor visualiza somente suas autorizações.
            if (req.usuario.perfil === PROFESSOR) {
                valores.push(req.usuario.id);

                condicoes.push(
                    `au.professor_id = $${valores.length}`
                );
            }

            if (busca) {
                valores.push(`%${busca}%`);

                condicoes.push(
                    `(a.nome ILIKE $${valores.length}
                    OR a.matricula ILIKE $${valores.length}
                    OR p.nome ILIKE $${valores.length}
                    OR t.nome ILIKE $${valores.length})`
                );
            }

            if (status) {
                const statusPermitidos = [
                    "ATIVA",
                    "CONCLUIDA",
                    "EXPIRADA"
                ];

                if (!statusPermitidos.includes(status)) {
                    return res.status(400).json({
                        erro: "Status inválido."
                    });
                }

                valores.push(status);

                condicoes.push(
                    `au.status = $${valores.length}`
                );
            }

            if (data_inicio) {
                valores.push(data_inicio);

                condicoes.push(
                    `au.horario_saida >= $${valores.length}::date`
                );
            }

            if (data_fim) {
                valores.push(data_fim);

                condicoes.push(
                    `au.horario_saida < ($${valores.length}::date + INTERVAL '1 day')`
                );
            }

            const where = condicoes.length
                ? `WHERE ${condicoes.join(" AND ")}`
                : "";

            const resultado = await consultar(
                `SELECT
                    au.id,
                    au.destino,
                    au.horario_saida,
                    au.horario_retorno,
                    au.status,
                    a.id AS aluno_id,
                    a.nome AS aluno,
                    a.matricula,
                    t.nome AS turma,
                    p.id AS professor_id,
                    p.nome AS professor
                 FROM autorizacoes au
                 INNER JOIN alunos a
                    ON a.id = au.aluno_id
                 INNER JOIN turmas t
                    ON t.id = a.turma_id
                 INNER JOIN usuarios p
                    ON p.id = au.professor_id
                 ${where}
                 ORDER BY au.horario_saida DESC
                 LIMIT 500`,
                valores
            );

            res.json(resultado.rows);

        } catch (erro) {
            console.error("Erro ao listar autorizações:", erro);

            res.status(500).json({
                erro: "Erro ao consultar autorizações."
            });
        }
    }
);

// ==========================================
// CONSULTAR AUTORIZAÇÃO POR ID
// ==========================================

app.get(
    "/api/autorizacoes/:id",
    autenticar,
    async (req, res) => {
        try {
            const { id } = req.params;

            if (!/^\d+$/.test(id)) {
                return res.status(400).json({
                    erro: "ID inválido."
                });
            }

            const valores = [id];
            let filtroProfessor = "";

            if (req.usuario.perfil === PROFESSOR) {
                valores.push(req.usuario.id);
                filtroProfessor = "AND au.professor_id = $2";
            }

            const resultado = await consultar(
                `SELECT
                    au.*,
                    a.nome AS aluno,
                    a.matricula,
                    t.nome AS turma,
                    p.nome AS professor
                 FROM autorizacoes au
                 INNER JOIN alunos a ON a.id = au.aluno_id
                 INNER JOIN turmas t ON t.id = a.turma_id
                 INNER JOIN usuarios p ON p.id = au.professor_id
                 WHERE au.id = $1
                 ${filtroProfessor}`,
                valores
            );

            if (resultado.rows.length === 0) {
                return res.status(404).json({
                    erro: "Autorização não encontrada."
                });
            }

            res.json(resultado.rows[0]);

        } catch (erro) {
            console.error(erro);

            res.status(500).json({
                erro: "Erro ao consultar autorização."
            });
        }
    }
);

// ==========================================
// REGISTRAR RETORNO DO ALUNO
// ==========================================

app.patch(
    "/api/autorizacoes/:id/retorno",
    autenticar,
    permitir(ADMIN, INSPETOR, PROFESSOR),
    async (req, res) => {
        try {
            const { id } = req.params;

            if (!/^\d+$/.test(id)) {
                return res.status(400).json({
                    erro: "ID inválido."
                });
            }

            const valores = [id];
            let filtroProfessor = "";

            if (req.usuario.perfil === PROFESSOR) {
                valores.push(req.usuario.id);

                filtroProfessor =
                    `AND professor_id = $${valores.length}`;
            }

            const resultado = await consultar(
                `UPDATE autorizacoes
                 SET
                    horario_retorno = CURRENT_TIMESTAMP,
                    status = 'CONCLUIDA'
                 WHERE id = $1
                   AND status = 'ATIVA'
                   ${filtroProfessor}
                 RETURNING *`,
                valores
            );

            if (resultado.rows.length === 0) {
                return res.status(404).json({
                    erro: "Autorização não encontrada, já concluída ou sem permissão."
                });
            }

            res.json({
                sucesso: true,
                mensagem: "Retorno registrado com sucesso!",
                autorizacao: resultado.rows[0]
            });

        } catch (erro) {
            console.error(erro);

            res.status(500).json({
                erro: "Erro ao registrar retorno."
            });
        }
    }
);

// ==========================================
// RELATÓRIOS
// ==========================================

app.get(
    "/api/relatorios",
    autenticar,
    permitir(ADMIN, INSPETOR, PROFESSOR),
    async (req, res) => {
        try {
            const { data_inicio, data_fim } = req.query;

            const valores = [];
            const condicoes = [];

            if (req.usuario.perfil === PROFESSOR) {
                valores.push(req.usuario.id);

                condicoes.push(
                    `au.professor_id = $${valores.length}`
                );
            }

            if (data_inicio) {
                valores.push(data_inicio);

                condicoes.push(
                    `au.horario_saida >= $${valores.length}::date`
                );
            }

            if (data_fim) {
                valores.push(data_fim);

                condicoes.push(
                    `au.horario_saida < ($${valores.length}::date + INTERVAL '1 day')`
                );
            }

            const where = condicoes.length
                ? `WHERE ${condicoes.join(" AND ")}`
                : "";

            const resultado = await consultar(
                `SELECT
                    au.id,
                    a.nome AS aluno,
                    a.matricula,
                    t.nome AS turma,
                    p.nome AS professor,
                    au.destino,
                    au.horario_saida,
                    au.horario_retorno,
                    au.status
                 FROM autorizacoes au
                 INNER JOIN alunos a ON a.id = au.aluno_id
                 INNER JOIN turmas t ON t.id = a.turma_id
                 INNER JOIN usuarios p ON p.id = au.professor_id
                 ${where}
                 ORDER BY au.horario_saida DESC`,
                valores
            );

            const registros = resultado.rows;

            const resumo = {
                total: registros.length,
                ativas: registros.filter(
                    item => item.status === "ATIVA"
                ).length,
                concluidas: registros.filter(
                    item => item.status === "CONCLUIDA"
                ).length,
                expiradas: registros.filter(
                    item => item.status === "EXPIRADA"
                ).length
            };

            res.json({
                resumo,
                registros
            });

        } catch (erro) {
            console.error("Erro nos relatórios:", erro);

            res.status(500).json({
                erro: "Não foi possível gerar os relatórios."
            });
        }
    }
);

// ==========================================
// RECUPERAÇÃO DE SENHA
// ==========================================

app.post("/api/recuperar-senha", async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                erro: "Informe seu e-mail."
            });
        }

        // Resposta genérica para não revelar
        // se determinado e-mail está cadastrado.

        const resultado = await consultar(
            `SELECT id FROM usuarios
             WHERE LOWER(email) = LOWER($1)`,
            [email.trim()]
        );

        if (resultado.rows.length > 0) {
            console.log(
                "Solicitação de recuperação para um usuário cadastrado."
            );
        }

        res.json({
            sucesso: true,
            mensagem: "Se o e-mail estiver cadastrado, ele poderá receber instruções de recuperação."
        });

    } catch (erro) {
        console.error(erro);

        res.status(500).json({
            erro: "Erro ao solicitar recuperação."
        });
    }
});

// ==========================================
// TRATAMENTO DE ROTAS INEXISTENTES
// ==========================================

app.use((req, res) => {
    res.status(404).json({
        erro: "Rota não encontrada.",
        rota: req.originalUrl
    });
});

// ==========================================
// INICIALIZAÇÃO
// ==========================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("----------------------------------");
    console.log(" AUTORIZA CESF - SERVIDOR ONLINE");
    console.log("----------------------------------");
    console.log(`Porta: ${PORT}`);
    console.log("Banco: Supabase PostgreSQL");
    console.log("----------------------------------");
});
