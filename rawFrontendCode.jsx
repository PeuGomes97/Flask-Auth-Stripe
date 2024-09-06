import React, { useEffect, useState } from 'react';
import axios from 'axios';

const App = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('auth_token');
      if (token) {
        try {
          const response = await axios.get('/verify', {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          if (response.status === 200) {
            setIsAuthenticated(true);
          }
        } catch (error) {
          console.error('Token verification failed:', error);
        }
      }
    };

    checkAuth();
  }, []);

  return (
    <div>
      {isAuthenticated ? <h1>Welcome!</h1> : <h1>Please log in</h1>}
    </div>
  );
};

export default App;
