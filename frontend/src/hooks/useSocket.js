import { useState, useEffect, useRef } from 'react';

export function useSocket(url) {
  const [data, setData] = useState(null);
  const socketRef = useRef(null);

  useEffect(() => {
    let cleanup = false;

    function connect() {
      if (cleanup) return;
      const socket = new WebSocket(url);
      socketRef.current = socket;

      socket.onmessage = (event) => {
        try {
          setData(JSON.parse(event.data));
        } catch (e) {
          console.error(`[Socket] Parse error on ${url}:`, e);
        }
      };

      socket.onclose = () => {
        setTimeout(connect, 3000);
      };

      socket.onerror = () => socket.close();
    }

    connect();

    return () => {
      cleanup = true;
      socketRef.current?.close();
    };
  }, [url]);

  return { data };
}
