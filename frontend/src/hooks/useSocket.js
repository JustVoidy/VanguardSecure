import { useState, useEffect, useRef } from 'react';

export function useSocket(url) {
  const [data, setData] = useState(null);
  const [connected, setConnected] = useState(false);
  const socketRef = useRef(null);

  useEffect(() => {
    let cleanup = false;

    function connect() {
      if (cleanup) return;
      
      const socket = new WebSocket(url);
      socketRef.current = socket;

      socket.onopen = () => {
        setConnected(true);
        console.log(`[Socket] Connected to ${url}`);
      };

      socket.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data);
          setData(parsed);
        } catch (e) {
          console.error(`[Socket] Error parsing message from ${url}:`, e);
        }
      };

      socket.onclose = () => {
        setConnected(false);
        console.log(`[Socket] Disconnected from ${url}. Retrying in 3s...`);
        setTimeout(connect, 3000);
      };

      socket.onerror = (error) => {
        console.error(`[Socket] Error on ${url}:`, error);
        socket.close();
      };
    }

    connect();

    return () => {
      cleanup = true;
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, [url]);

  return { data, connected };
}
