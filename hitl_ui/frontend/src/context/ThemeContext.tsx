import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

type Theme = "light" | "dark";

interface ThemeState {
  theme: Theme;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeState>({
  theme: "light",
  toggleTheme: () => undefined,
});

function getInitialTheme(): Theme {
  const stored = localStorage.getItem("hitl_theme");
  if (stored === "dark" || stored === "light") return stored;
  // Fall back to OS preference
  if (window.matchMedia("(prefers-color-scheme: dark)").matches) return "dark";
  return "light";
}

function applyTheme(theme: Theme): void {
  if (theme === "dark") {
    document.documentElement.classList.add("dark");
  } else {
    document.documentElement.classList.remove("dark");
  }
}

export function ThemeProvider({
  children,
}: {
  children: React.ReactNode;
}): React.ReactElement {
  const [theme, setTheme] = useState<Theme>(getInitialTheme);

  // Apply on mount and whenever theme changes
  useEffect(() => {
    applyTheme(theme);
    localStorage.setItem("hitl_theme", theme);
  }, [theme]);

  // Also listen for OS-level changes when no explicit preference is stored
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = (e: MediaQueryListEvent) => {
      if (!localStorage.getItem("hitl_theme")) {
        const next: Theme = e.matches ? "dark" : "light";
        setTheme(next);
      }
    };
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  }, []);

  const value = useMemo<ThemeState>(
    () => ({ theme, toggleTheme }),
    [theme, toggleTheme],
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

export function useTheme(): ThemeState {
  return useContext(ThemeContext);
}
