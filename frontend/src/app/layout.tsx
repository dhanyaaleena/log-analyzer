"use client";

// Metadata import removed as it's not used
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { AppBar, Toolbar, Typography, Button, Box, Container } from "@mui/material";
import LogoutIcon from "@mui/icons-material/Logout";
import { ThemeProvider, createTheme } from "@mui/material/styles";
import CssBaseline from "@mui/material/CssBaseline";
import { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import { log } from "console";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const neumorphicTheme = createTheme({
  palette: {
    mode: "light",
    primary: {
      main: "#bfc4ce",
      light: "#e0e3ea",
    },
    background: {
      default: "#f7f8fa",
      paper: "#fff",
    },
    text: {
      primary: "#222",
      secondary: "#555",
    },
  },
  shape: {
    borderRadius: 20,
  },
  typography: {
    fontFamily: 'Geist, Inter, Roboto, Arial',
    fontWeightBold: 700,
    h5: {
      fontWeight: 700,
      fontSize: '2rem',
      letterSpacing: '-0.5px',
    },
    body1: {
      fontSize: '1.1rem',
    },
  },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          borderRadius: 20,
          boxShadow: '0 8px 32px rgba(0,0,0,0.12)',
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 20,
          boxShadow: '0 8px 32px rgba(0,0,0,0.12)',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 9999,
          textTransform: 'none',
          fontWeight: 600,
          boxShadow: 'none',
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          borderRadius: 0,
          boxShadow: '0 4px 20px rgba(0,0,0,0.15)',
          background: '#fff',
          color: '#222',
        },
      },
    },
    MuiToolbar: {
      styleOverrides: {
        root: {
          minHeight: 64,
        },
      },
    },
  },
});

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isClient, setIsClient] = useState(false);
  const router = useRouter();
  const pathname = usePathname();
  const isDashboard = pathname.startsWith('/dashboard');

  useEffect(() => {
    setIsClient(true);
    
    if (typeof window !== "undefined") {
      const token = window.localStorage.getItem("token");
      console.log("Layout: Token check -", !!token);
      setIsLoggedIn(!!token);
    }
  }, [pathname]);

  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased`} style={{ background: '#f7f8fa' }}>
        <ThemeProvider theme={neumorphicTheme}>
          <CssBaseline />
          <AppBar position="sticky" color="default" elevation={1} sx={{ top: 0, zIndex: 1100 }}>
            <Toolbar>
              <Typography variant="h6" sx={{ flexGrow: 1, fontWeight: 700, color: '#222', letterSpacing: '-1px' }}>
                Log Analyzer
              </Typography>
              {isClient && isLoggedIn && (
                <>
                  {isDashboard && (
                    <Button color="inherit" href="/log-analyzer">Log Files Dashboard</Button>
                  )}
                  <Button
                    color="inherit"
                    startIcon={<LogoutIcon />}
                    onClick={() => {
                      window.localStorage.removeItem("token");
                      router.replace("/login");
                    }}
                    sx={{ ml: 2 }}
                  >
                    Logout
                  </Button>
                </>
              )}
            </Toolbar>
          </AppBar>
          {isDashboard ? (
            <Box sx={{ minHeight: "80vh", py: 4 }}>{children}</Box>
          ) : (
          <Container maxWidth="md" sx={{ minHeight: "80vh", py: 4 }}>{children}</Container>
          )}
          <Container maxWidth="md" disableGutters>
            <Box component="footer" sx={{ textAlign: "center", py: 2, color: "#555", width: '100%' }}>
              &copy; {new Date().getFullYear()} Log Analyzer. All rights reserved.
            </Box>
          </Container>
        </ThemeProvider>
      </body>
    </html>
  );
}
