import { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Shield } from 'lucide-react';
import { fetchAPI } from '../utils/api';
import type { Suggestion } from '../utils/types';

interface SearchInputProps {
  placeholder?: string;
  wrapperClass?: string;
  initialValue?: string;
  onSearch?: (query: string) => void;
}

export default function SearchInput({
  placeholder = 'Search CWE-79, sql injection, buffer overflow...',
  wrapperClass = 'search-container',
  initialValue = '',
  onSearch,
}: SearchInputProps) {
  const navigate = useNavigate();
  const [value, setValue] = useState(initialValue);
  const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>();
  const wrapperRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setValue(initialValue);
  }, [initialValue]);

  // Close suggestions on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setShowSuggestions(false);
      }
    };
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, []);

  const handleSearch = useCallback(() => {
    const q = value.trim();
    if (!q) return;

    setShowSuggestions(false);

    const cweMatch = q.match(/^(?:CWE-?)?(\d+)$/i);
    if (cweMatch) {
      navigate(`/cwe/${cweMatch[1]}`);
    } else if (onSearch) {
      onSearch(q);
    } else {
      navigate(`/search?keyword=${encodeURIComponent(q)}`);
    }
  }, [value, navigate, onSearch]);

  const handleInput = useCallback(
    (q: string) => {
      setValue(q);
      if (debounceRef.current) clearTimeout(debounceRef.current);

      if (q.trim().length < 2) {
        setShowSuggestions(false);
        return;
      }

      debounceRef.current = setTimeout(async () => {
        try {
          const data = await fetchAPI<Suggestion[]>(
            `/api/cwe/suggestions?q=${encodeURIComponent(q.trim())}`
          );
          if (data.length > 0) {
            setSuggestions(data);
            setShowSuggestions(true);
          } else {
            setShowSuggestions(false);
          }
        } catch {
          setShowSuggestions(false);
        }
      }, 250);
    },
    []
  );

  return (
    <div ref={wrapperRef} style={{ position: 'relative' }}>
      <div className={wrapperClass}>
        <Search className="search-icon" size={18} />
        <input
          type="text"
          value={value}
          onChange={(e) => handleInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              handleSearch();
            }
          }}
          placeholder={placeholder}
          autoComplete="off"
        />
        <button onClick={handleSearch}>Search</button>
      </div>

      {showSuggestions && suggestions.length > 0 && (
        <div className="suggestions-dropdown active">
          {suggestions.map((item, i) => {
            const icon =
              item.type === 'cwe' ? (
                <Shield size={15} className="suggestion-icon-cwe" />
              ) : (
                <Search size={15} className="suggestion-icon-keyword" />
              );

            if (item.action) {
              return (
                <a
                  key={i}
                  href={item.action}
                  className="suggestion-item"
                  onClick={(e) => {
                    e.preventDefault();
                    setShowSuggestions(false);
                    navigate(item.action!);
                  }}
                >
                  {icon}
                  <span>{item.text}</span>
                  <span className="suggestion-type">{item.type}</span>
                </a>
              );
            }

            return (
              <div key={i} className="suggestion-item suggestion-tip">
                {icon}
                <span>{item.text}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
