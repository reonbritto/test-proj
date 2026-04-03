import { Loader2 } from 'lucide-react';

interface LoadingProps {
  message?: string;
}

export default function Loading({ message = 'Loading...' }: LoadingProps) {
  return (
    <div className="loading">
      <Loader2 className="spinner" size={28} />
      <p>{message}</p>
    </div>
  );
}
