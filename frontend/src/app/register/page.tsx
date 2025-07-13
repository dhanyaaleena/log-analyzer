"use client";
import { useState } from "react";
import { Paper, Typography, TextField, Button, Box, CircularProgress, Avatar, Divider, Alert, Link } from "@mui/material";
import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import { useRouter } from "next/navigation";
import { useTheme } from "@mui/material/styles";

const API_BASE = (process.env.NEXT_PUBLIC_API_BASE || "http://localhost:5000") + "/auth";

export default function RegisterPage() {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const theme = useTheme();
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setSuccess("");
    try {
      const res = await fetch(`${API_BASE}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.msg || "Something went wrong");
      } else {
        setSuccess("Registration successful! Redirecting to login...");
        setTimeout(() => router.replace("/login"), 1500);
      }
    } catch (err) { // eslint-disable-line @typescript-eslint/no-unused-vars
      setError("Network error");
    }
    setLoading(false);
  };

  return (
    <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh" sx={{ bgcolor: 'background.default' }}>
      <Paper elevation={3} sx={{ maxWidth: 420, width: "100%", p: 4, borderRadius: 5, boxShadow: '0 4px 24px rgba(0,0,0,0.04)' }}>
        <Box display="flex" flexDirection="column" alignItems="center" mb={2}>
          <Avatar sx={{ bgcolor: "primary.light", mb: 1, width: 56, height: 56 }}>
            <LockOutlinedIcon sx={{ color: '#555', fontSize: 32 }} />
          </Avatar>
          <Typography variant="h5" fontWeight={700} gutterBottom>Register</Typography>
        </Box>
        <Divider sx={{ mb: 3 }} />
        <form onSubmit={handleSubmit}>
          <TextField
            label="Username"
            variant="outlined"
            fullWidth
            margin="normal"
            value={username}
            onChange={e => setUsername(e.target.value)}
            required
            sx={{ input: { color: 'text.primary' } }}
          />
          <TextField
            label="Password"
            type="password"
            variant="outlined"
            fullWidth
            margin="normal"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
            sx={{ input: { color: 'text.primary' } }}
          />
          {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
          {success && <Alert severity="success" sx={{ mt: 2 }}>{success}</Alert>}
          <Button
            type="submit"
            variant="contained"
            color="inherit"
            fullWidth
            sx={{ mt: 3, fontWeight: 700, py: 1.5, fontSize: '1.1rem', bgcolor: 'primary.light', color: '#555', '&:hover': { bgcolor: 'primary.main', color: '#222' } }}
            disabled={loading}
            startIcon={loading ? <CircularProgress size={20} /> : null}
          >
            {loading ? "Registering..." : "Register"}
          </Button>
        </form>
        <Divider sx={{ my: 3 }} />
        <Typography align="center" color="text.secondary">
          Already have an account?{' '}
          <Link href="/log-analyzer/login" underline="hover" color="primary.main" sx={{ fontWeight: 600 }}>
            Login
          </Link>
        </Typography>
      </Paper>
    </Box>
  );
} 