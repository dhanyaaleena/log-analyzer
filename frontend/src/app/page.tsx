"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Box, Paper, Typography, Button, Divider, List, ListItem, ListItemText, ListItemSecondaryAction, Alert, LinearProgress } from "@mui/material";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import AssessmentIcon from "@mui/icons-material/Assessment";
import api from "../lib/api";

interface StoredFile {
  id: string;
  name: string;
  uploaded: string;
}

export default function DashboardPage() {
  const router = useRouter();
  const [files, setFiles] = useState<StoredFile[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const filesPerPage = 5;

  useEffect(() => {
    // Load files from localStorage and sort by upload time (newest first)
    const stored = window.localStorage.getItem("log_files");
    if (stored) {
      const filesList = JSON.parse(stored);
      // Sort by upload time, newest first
      const sortedFiles = filesList.sort((a: StoredFile, b: StoredFile) => 
        new Date(b.uploaded).getTime() - new Date(a.uploaded).getTime()
      );
      setFiles(sortedFiles);
    }
  }, []);

  const handleView = (fileId: string) => {
    router.push(`/dashboard?file_id=${fileId}`);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError("");
      setMessage("");
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
      const uploadRes = await api.post("/api/upload", formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "multipart/form-data",
        },
      });
      const fileId = uploadRes.data.logfile_id;
      // Store file info in localStorage
      const fileInfo = { id: fileId, name: file.name, uploaded: new Date().toISOString() };
      let files = [];
      try {
        files = JSON.parse(window.localStorage.getItem("log_files") || "[]");
      } catch {}
      files.push(fileInfo);
      // Sort by upload time, newest first
      const sortedFiles = files.sort((a: StoredFile, b: StoredFile) => 
        new Date(b.uploaded).getTime() - new Date(a.uploaded).getTime()
      );
      window.localStorage.setItem("log_files", JSON.stringify(sortedFiles));
      setFiles(sortedFiles);
      setCurrentPage(1); // Reset to first page to show newest files
      setMessage("File uploaded. Running analysis...");
      // Trigger analysis
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const analysisRes = await api.post(
        "/api/analysis/run",
        { file_id: fileId, use_llm: true },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );
      setMessage("File uploaded and analyzed successfully! Redirecting to analysis...");
      setFile(null);
      // Redirect to SOC dashboard for the uploaded file
      setTimeout(() => {
        router.push(`/dashboard?file_id=${fileId}`);
      }, 1500);
    } catch (err: any) { // eslint-disable-line @typescript-eslint/no-explicit-any
      setError(err?.response?.data?.msg || "Upload or analysis failed");
    } finally {
      setUploading(false);
    }
  };

  return (
    <Box display="flex" flexDirection="column" alignItems="center" minHeight="80vh" justifyContent="center">
      <Paper elevation={3} sx={{ maxWidth: 700, width: "100%", p: 4, borderRadius: 5, boxShadow: '0 4px 24px rgba(0,0,0,0.04)' }}>
        <Box display="flex" flexDirection="column" alignItems="center" mb={2}>
          <AssessmentIcon sx={{ fontSize: 44, mb: 1, color: '#555' }} />
          <Typography variant="h5" fontWeight={700} gutterBottom>Log Files Dashboard</Typography>
        </Box>
        <Divider sx={{ mb: 3 }} />
        
        {/* Upload Section */}
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
            sx={{ mb: 3, fontWeight: 700, borderRadius: 9999, py: 1.2, fontSize: '1.1rem', bgcolor: 'primary.light', color: '#555', '&:hover': { bgcolor: 'primary.main', color: '#222' } }}
          >
            {uploading ? "Uploading..." : "Upload & Analyze"}
          </Button>
          {message && <Alert severity="success" sx={{ mb: 2 }}>{message}</Alert>}
          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        </form>
        
        <Divider sx={{ mb: 3 }} />
        <Typography variant="subtitle1" fontWeight={600} gutterBottom>Uploaded Files</Typography>
        {files.length === 0 ? (
          <Typography color="text.secondary">No files uploaded yet.</Typography>
        ) : (
          <>
            <List>
              {files
                .slice((currentPage - 1) * filesPerPage, currentPage * filesPerPage)
                .map((file) => (
                  <ListItem key={file.id} divider>
                    <ListItemText
                      primary={file.name}
                      secondary={`Uploaded: ${new Date(file.uploaded).toLocaleString()}`}
                    />
                    <ListItemSecondaryAction>
                      <Button
                        variant="contained"
                        color="success"
                        onClick={() => handleView(file.id)}
                      >
                        SOC Analysis
                      </Button>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
            </List>
            
            {/* Pagination Controls */}
            {files.length > filesPerPage && (
              <Box display="flex" justifyContent="space-between" alignItems="center" mt={2}>
                <Button
                  variant="outlined"
                  disabled={currentPage === 1}
                  onClick={() => setCurrentPage(currentPage - 1)}
                  sx={{ borderRadius: 9999, px: 3 }}
                >
                  Back
                </Button>
                <Typography variant="body2" color="text.secondary">
                  Page {currentPage} of {Math.ceil(files.length / filesPerPage)}
                </Typography>
                <Button
                  variant="outlined"
                  disabled={currentPage >= Math.ceil(files.length / filesPerPage)}
                  onClick={() => setCurrentPage(currentPage + 1)}
                  sx={{ borderRadius: 9999, px: 3 }}
                >
                  Next
                </Button>
              </Box>
            )}
          </>
        )}
      </Paper>
    </Box>
  );
}
