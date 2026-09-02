import "./App.css";

function App() {
  return (
    <div className="app">

      {/* Sidebar */}
      <aside className="sidebar">
        <div className="logo">
          <div className="logo-icon">⚡</div>
          <div>
            <h2>Threat<span>Intel</span></h2>
            <p>SECURITY PLATFORM</p>
          </div>
        </div>

        <nav>
          <p className="menu-title">MAIN</p>

          <a className="nav-item active">
            <span>◉</span>
            Dashboard
          </a>

          <a className="nav-item">
            <span>⌕</span>
            IOC Search
          </a>

          <a className="nav-item">
            <span>◈</span>
            ThreatFox
          </a>

          <p className="menu-title">SYSTEM</p>

          <a className="nav-item">
            <span>⚙</span>
            Settings
          </a>
        </nav>

        <div className="system-status">
          <div className="status-dot"></div>
          <div>
            <strong>System Online</strong>
            <small>All services operational</small>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main">

        {/* Header */}
        <header className="header">
          <div>
            <p className="breadcrumb">SECURITY / OVERVIEW</p>
            <h1>Threat Intelligence Dashboard</h1>
          </div>

          <div className="header-right">
            <div className="live">
              <span></span>
              LIVE
            </div>

            <div className="profile">
              <div className="avatar">S</div>
              <div>
                <strong>Security Analyst</strong>
                <small>Administrator</small>
              </div>
            </div>
          </div>
        </header>

        {/* Stats */}
        <section className="stats">

          <div className="stat-card">
            <div className="stat-top">
              <span>Total IOCs</span>
              <div className="stat-icon">◉</div>
            </div>
            <h2>1,284</h2>
            <p className="positive">↑ 12.5% <span>vs last week</span></p>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>Malicious IPs</span>
              <div className="stat-icon">⌁</div>
            </div>
            <h2>327</h2>
            <p className="danger">↑ 8.2% <span>vs last week</span></p>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>Domains</span>
              <div className="stat-icon">◈</div>
            </div>
            <h2>642</h2>
            <p className="positive">↑ 5.7% <span>vs last week</span></p>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>High Risk</span>
              <div className="stat-icon warning">!</div>
            </div>
            <h2>89</h2>
            <p className="danger">↑ 18.4% <span>requires attention</span></p>
          </div>

        </section>

        {/* Content Grid */}
        <section className="content-grid">

          {/* Threat Activity */}
          <div className="panel activity-panel">
            <div className="panel-header">
              <div>
                <h3>Threat Activity</h3>
                <p>IOC activity over the last 7 days</p>
              </div>

              <select>
                <option>Last 7 days</option>
                <option>Last 30 days</option>
              </select>
            </div>

            <div className="chart">
              <div className="chart-line"></div>

              <div className="chart-bars">
                <div style={{ height: "35%" }}></div>
                <div style={{ height: "48%" }}></div>
                <div style={{ height: "42%" }}></div>
                <div style={{ height: "67%" }}></div>
                <div style={{ height: "55%" }}></div>
                <div style={{ height: "82%" }}></div>
                <div style={{ height: "72%" }}></div>
              </div>

              <div className="days">
                <span>MON</span>
                <span>TUE</span>
                <span>WED</span>
                <span>THU</span>
                <span>FRI</span>
                <span>SAT</span>
                <span>SUN</span>
              </div>
            </div>
          </div>

          {/* Threat Distribution */}
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Threat Distribution</h3>
                <p>Indicators by type</p>
              </div>
            </div>

            <div className="distribution">
              <div className="circle">
                <strong>1,284</strong>
                <span>Total</span>
              </div>

              <div className="legend">
                <div>
                  <span className="legend-dot"></span>
                  IP Address
                  <strong>327</strong>
                </div>

                <div>
                  <span className="legend-dot"></span>
                  Domain
                  <strong>642</strong>
                </div>

                <div>
                  <span className="legend-dot"></span>
                  URL
                  <strong>215</strong>
                </div>

                <div>
                  <span className="legend-dot"></span>
                  Hash
                  <strong>100</strong>
                </div>
              </div>
            </div>
          </div>

        </section>

        {/* Recent Indicators */}
        <section className="panel recent">

          <div className="panel-header">
            <div>
              <h3>Recent Threat Indicators</h3>
              <p>Latest intelligence collected from threat sources</p>
            </div>

            <button>View All →</button>
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>INDICATOR</th>
                  <th>TYPE</th>
                  <th>SOURCE</th>
                  <th>THREAT</th>
                  <th>CONFIDENCE</th>
                  <th>STATUS</th>
                </tr>
              </thead>

              <tbody>

                <tr>
                  <td>185.220.101.42</td>
                  <td><span className="type">IP</span></td>
                  <td>ThreatFox</td>
                  <td>Malware</td>
                  <td>92%</td>
                  <td><span className="badge high">HIGH</span></td>
                </tr>

                <tr>
                  <td>malicious-domain.xyz</td>
                  <td><span className="type">DOMAIN</span></td>
                  <td>ThreatFox</td>
                  <td>Phishing</td>
                  <td>87%</td>
                  <td><span className="badge high">HIGH</span></td>
                </tr>

                <tr>
                  <td>45.148.10.23</td>
                  <td><span className="type">IP</span></td>
                  <td>ThreatFox</td>
                  <td>C2</td>
                  <td>76%</td>
                  <td><span className="badge medium">MEDIUM</span></td>
                </tr>

              </tbody>
            </table>
          </div>

        </section>

      </main>
    </div>
  );
}

export default App;
