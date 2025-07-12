"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, Typography, Button, Box, LinearProgress, Alert, Divider, Paper } from "@mui/material";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import axios from "axios";

export default function UploadPage() {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [message, setMessage] = useState("");
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const token = window.localStorage.getItem("token");
    if (!token) {
      router.replace("/login");
    }
  }, [router]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setMessage("");
    if (!file) return;
    setUploading(true);
    try {
      const token = window.localStorage.getItem("token");
      const formData = new FormData();
      formData.append("file", file);
      // Upload file
      const uploadRes = await axios.post(
        "/api/upload",
        formData,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "multipart/form-data",
          },
        }
      );
      const fileId = uploadRes.data.logfile_id;
      // Store file info in localStorage
      const fileInfo = { id: fileId, name: file.name, uploaded: new Date().toISOString() };
      let files = [];
      try {
        files = JSON.parse(window.localStorage.getItem("log_files") || "[]");
      } catch {}
      files.push(fileInfo);
      window.localStorage.setItem("log_files", JSON.stringify(files));
      setMessage("File uploaded. Running analysis...");
      // Trigger analysis
      const analysisRes = await axios.post(
        "/api/analysis/run",
        { file_id: fileId, use_llm: true },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );
      // Redirect to SOC dashboard with file_id as query param
      router.push(`/dashboard?file_id=${fileId}`);
    } catch (err: any) {
      setError(err?.response?.data?.msg || "Upload or analysis failed");
    } finally {
      setUploading(false);
      setFile(null);
    }
  };

  return (
    <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh" sx={{ bgcolor: 'background.default' }}>
      <Paper elevation={3} sx={{ maxWidth: 520, width: "100%", p: 4, borderRadius: 5, boxShadow: '0 4px 24px rgba(0,0,0,0.04)' }}>
        <Box display="flex" flexDirection="column" alignItems="center" mb={2}>
          <CloudUploadIcon sx={{ fontSize: 44, mb: 1, color: '#555' }} />
          <Typography variant="h5" fontWeight={700} gutterBottom>Upload Log File</Typography>
        </Box>
        <Divider sx={{ mb: 3 }} />
        <form onSubmit={handleUpload}>
          <Button
            variant="outlined"
            component="label"
            fullWidth
            startIcon={<CloudUploadIcon sx={{ color: '#555' }} />}
            sx={{ mb: 2, color: '#555', borderColor: 'primary.light', borderRadius: 9999, py: 1.2, fontWeight: 600, bgcolor: 'primary.light', '&:hover': { bgcolor: 'primary.main', color: '#222' } }}
          >
            {file ? file.name : "Select .log or .txt file"}
            <input
              type="file"
              accept=".log,.txt"
              hidden
              onChange={handleFileChange}
              required
            />
          </Button>
          {uploading && <LinearProgress sx={{ mb: 2 }} />}
          <Button
            type="submit"
            variant="contained"
            color="inherit"
            fullWidth
            disabled={uploading || !file}
            sx={{ fontWeight: 700, borderRadius: 9999, py: 1.2, fontSize: '1.1rem', bgcolor: 'primary.light', color: '#555', '&:hover': { bgcolor: 'primary.main', color: '#222' } }}
          >
            {uploading ? "Uploading..." : "Upload & Analyze"}
          </Button>
          {message && <Alert severity="success" sx={{ mt: 2 }}>{message}</Alert>}
          {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
        </form>
      </Paper>
    </Box>
  );
} 