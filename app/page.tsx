const modules = [
  { icon: "👥", name: "Plantel", detail: "Jogadores, posições, CA e PA", status: "Em preparação" },
  { icon: "📅", name: "Épocas", detail: "Histórico e evolução por temporada", status: "Planeado" },
  { icon: "🔄", name: "Transferências", detail: "Entradas, saídas e empréstimos", status: "Planeado" },
  { icon: "📊", name: "Estatísticas", detail: "Desempenho individual e coletivo", status: "Planeado" },
  { icon: "♟️", name: "Táticas", detail: "Formações, onze inicial e funções", status: "Planeado" },
  { icon: "🏆", name: "Competições", detail: "Classificações e palmarés", status: "Planeado" }
];

export default function Home() {
  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">FM</span><span>CAREER HUB</span></div>
        <div className="side-label">ESPAÇO DE TRABALHO</div>
        <a className="nav-item active" href="/">⌂ <span>Visão geral</span></a>
        {modules.map((item) => <a className="nav-item" href="#modulos" key={item.name}>{item.icon} <span>{item.name}</span></a>)}
        <div className="sidebar-foot">O teu percurso. A tua história.</div>
      </aside>

      <section className="main">
        <header className="topbar"><span>FM CAREER HUB <span className="muted">/ Visão geral</span></span><span className="season-pill">● Espaço pessoal</span></header>
        <div className="content">
          <div className="eyebrow">CENTRO DE COMANDO</div>
          <h1>A tua carreira,<br /><span>num só lugar.</span></h1>
          <p className="intro">Organiza o plantel, acompanha cada época e constrói o arquivo completo da tua jornada no Football Manager.</p>

          <div className="welcome-panel">
            <div><div className="panel-kicker">BEM-VINDO AO FM CAREER HUB</div><h2>Está na hora de começar.</h2><p>Esta é a base da tua plataforma de gestão de carreira. Vamos construir cada módulo sem perder o histórico dos teus jogadores.</p></div>
            <div className="panel-ball">⚽</div>
          </div>

          <div className="section-heading" id="modulos"><div><div className="eyebrow">A PLATAFORMA</div><h2>Os teus módulos</h2></div><span className="muted small">6 áreas previstas</span></div>
          <div className="module-grid">
            {modules.map((item, index) => <article className="module-card" key={item.name}><div className="module-top"><span className="module-icon">{item.icon}</span><span className="module-number">0{index + 1}</span></div><h3>{item.name}</h3><p>{item.detail}</p><span className="module-status">{item.status}</span></article>)}
          </div>
          <footer>FM CAREER HUB <span>•</span> Construído para acompanhar todas as épocas.</footer>
        </div>
      </section>
    </main>
  );
}
