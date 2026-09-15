import { Link, Navigate, NavLink, Route, Routes } from "react-router";
import { Upload } from "lucide-react";
import logo from "../logo.png";
import { CatalogPage } from "./pages/catalog_page";
import { CasePage } from "./pages/case_page";
import { UploadPage } from "./pages/upload_page";

export default function App() {
  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--text)]">
      <header className="sticky top-0 z-30 border-b border-[var(--border)] bg-[color:var(--background-alpha)]">
        <div className="mx-auto flex max-w-[1680px] items-center gap-3 px-4 py-3 sm:px-6">
          <Link className="flex min-w-0 items-center" to="/cases">
            <img alt="SecureMail" className="h-9 w-auto max-w-[12rem] object-contain" src={logo} />
          </Link>
          <NavLink
            className={({ isActive }) =>
              `app-upload-action ${isActive ? "active" : ""}`
            }
            to="/upload"
          >
            <Upload size={15} />
            <span>Upload capture</span>
          </NavLink>
        </div>
      </header>
      <main className="mx-auto min-w-0 max-w-[1680px] p-4 sm:p-6 lg:p-8">
        <Routes>
          <Route element={<Navigate replace to="/cases" />} path="/" />
          <Route element={<CatalogPage />} path="/cases" />
          <Route element={<CasePage />} path="/cases/:case_id" />
          <Route element={<UploadPage />} path="/upload" />
          <Route element={<Navigate replace to="/cases" />} path="*" />
        </Routes>
      </main>
    </div>
  );
}
