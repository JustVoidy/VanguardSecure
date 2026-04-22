import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import AdminLoginPage from './Pages/AdminLoginPage';
import App from './App';

function Root() {
// ✅ Change to admin login state
const [isAdminLoggedIn, setIsAdminLoggedIn] = React.useState(
() => localStorage.getItem('adminLoggedIn') === 'true'
);

function handleSetAdminLoggedIn(val) {
setIsAdminLoggedIn(val);
localStorage.setItem('adminLoggedIn', val);
}

return ( <BrowserRouter> <Routes>


    {/* 🔐 Admin Login Page */}
    <Route
      path="/"
      element={
        isAdminLoggedIn ? (
          <Navigate to="/dashboard" />
        ) : (
          <AdminLoginPage onLogin={handleSetAdminLoggedIn} />
        )
      }
    />

    {/* 📊 Dashboard (Protected Route) */}
    <Route
      path="/dashboard"
      element={
        isAdminLoggedIn ? (
          <App />
        ) : (
          <Navigate to="/" />
        )
      }
    />

    {/* 🔁 Fallback */}
    <Route path="*" element={<Navigate to="/" />} />

  </Routes>
</BrowserRouter>

);
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<Root />);

