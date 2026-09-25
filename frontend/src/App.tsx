import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { api } from "./api";
import type { ProjectPage, Readiness } from "./api";
import "./App.css";

export default function App() {
  const [page, setPage] = useState<ProjectPage | null>(null);
  const [offset, setOffset] = useState(0);
  const [health, setHealth] = useState<Readiness | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async (pageOffset: number) => {
    const [projects, readiness] = await Promise.allSettled([
      api.projects(pageOffset),
      api.readiness(),
    ]);
    if (projects.status === "fulfilled") {
      setPage(projects.value);
      setError("");
    } else {
      setPage(null);
      setError(
        projects.reason instanceof Error
          ? projects.reason.message
          : "Không tải được dự án.",
      );
    }
    setHealth(readiness.status === "fulfilled" ? readiness.value : null);
    setLoading(false);
  }, []);
  useEffect(() => {
    // State updates in load occur after API requests settle, not synchronously.
    // oxlint-disable-next-line react/set-state-in-effect
    void load(offset);
  }, [load, offset]);

  function changePage(nextOffset: number) {
    setLoading(true);
    setOffset(nextOffset);
  }

  function refresh() {
    setLoading(true);
    void load(offset);
  }

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!name.trim() || saving) return;
    setSaving(true);
    setNotice("");
    setError("");
    try {
      const project = await api.createProject(name.trim(), description);
      setName("");
      setDescription("");
      setNotice(`Đã tạo dự án “${project.name}”.`);
      if (offset === 0) await load(0);
      else changePage(0);
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Không tạo được dự án.",
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="shell">
      <header>
        <a href="/" className="brand">
          <span className="brand-icon">S</span>Security Triage
        </a>
        <a href="/api/docs" target="_blank" rel="noreferrer">
          API docs ↗
        </a>
      </header>
      <main>
        <section className="intro">
          <span className="eyebrow">WORKSPACE / DỰ ÁN</span>
          <h1>Không gian phân tích mã nguồn</h1>
          <p>
            Quản lý dự án cho quy trình sàng lọc và thẩm định cảnh báo Semgrep &
            CodeQL.
          </p>
        </section>
        <div className="status-strip" aria-label="Trạng thái hạ tầng">
          <span className="muted">Kết nối dịch vụ</span>
          {Object.entries({
            postgres: "PostgreSQL",
            redis: "Redis",
            storage: "SeaweedFS",
          }).map(([key, label]) => (
            <span className="service" key={key}>
              <span
                className={`dot ${health?.checks[key] === "ok" ? "online" : ""}`}
              />
              {label}
              <small>
                {loading
                  ? "Đang kiểm tra"
                  : health?.checks[key] === "ok"
                    ? "Sẵn sàng"
                    : "Chưa kết nối"}
              </small>
            </span>
          ))}
          <button
            className="secondary"
            disabled={loading || saving}
            onClick={refresh}
          >
            Kiểm tra lại
          </button>
        </div>
        {error && (
          <div className="message error" role="alert">
            {error}
          </div>
        )}
        {notice && (
          <div className="message success" role="status">
            {notice}
          </div>
        )}
        <div className="workspace-grid">
          <section aria-busy={loading}>
            <div className="section-title">
              <h2>Dự án của bạn</h2>
              <span className="tag">{page?.total ?? "—"}</span>
            </div>
            {loading ? (
              <div className="empty">Đang tải dự án…</div>
            ) : page?.items.length ? (
              <div className="project-list">
                {page.items.map((project) => (
                  <article className="project-card" key={project.id}>
                    <h3>{project.name}</h3>
                    <p>{project.description || "Chưa có mô tả."}</p>
                    <div className="project-footer">
                      <time dateTime={project.created_at}>
                        {new Date(project.created_at).toLocaleDateString(
                          "vi-VN",
                        )}
                      </time>
                      <span className="tag">Đã tạo</span>
                    </div>
                  </article>
                ))}
              </div>
            ) : (
              <div className="empty">
                <h3>
                  {error
                    ? "Chưa tải được dữ liệu"
                    : "Bắt đầu với dự án đầu tiên"}
                </h3>
                <p>
                  {error
                    ? "Kiểm tra kết nối rồi thử lại."
                    : "Đặt tên và mô tả dự án bằng biểu mẫu bên cạnh."}
                </p>
              </div>
            )}
            {page && page.total > page.limit && (
              <nav className="pagination" aria-label="Phân trang dự án">
                <button
                  className="secondary"
                  disabled={offset === 0 || loading || saving}
                  onClick={() => changePage(Math.max(0, offset - 12))}
                >
                  Trước
                </button>
                <span>Trang {Math.floor(offset / 12) + 1}</span>
                <button
                  className="secondary"
                  disabled={offset + 12 >= page.total || loading || saving}
                  onClick={() => changePage(offset + 12)}
                >
                  Sau
                </button>
              </nav>
            )}
          </section>
          <aside>
            <form onSubmit={create}>
              <span className="eyebrow">DỰ ÁN MỚI</span>
              <h2>Tạo dự án</h2>
              <label htmlFor="name">Tên dự án</label>
              <input
                id="name"
                required
                maxLength={120}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Ví dụ: Python command injection"
              />
              <label htmlFor="description">
                Mô tả <span className="muted">(tùy chọn)</span>
              </label>
              <textarea
                id="description"
                rows={4}
                maxLength={4000}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Phạm vi mã nguồn và mục tiêu đánh giá…"
              />
              <button
                className="primary"
                disabled={saving || loading || !name.trim()}
              >
                {saving ? "Đang tạo…" : "+ Tạo dự án"}
              </button>
            </form>
            <div className="scope-note">
              <strong>Bản khởi tạo · 0.1</strong>
              <p>
                Đã có quản lý dự án và kiểm tra kết nối. Upload mã nguồn, chạy
                công cụ và thẩm định cảnh báo sẽ được bổ sung ở các bước tiếp
                theo.
              </p>
            </div>
          </aside>
        </div>
      </main>
      <footer>
        Security Triage <span>Semgrep + CodeQL · JS/TS & Python</span>
      </footer>
    </div>
  );
}
