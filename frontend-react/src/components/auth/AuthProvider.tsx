import React, { useEffect, useState } from 'react';
import { useDispatch } from 'react-redux';
import { useGetCurrentUserQuery, useVerifyTokenMutation } from '../../store/api/authApi';
import { setCredentials, clearCredentials, setLoading } from '../../store/slices/authSlice';
import { tokenStorage, isTokenExpired } from '../../utils/auth';

interface AuthProviderProps {
  children: React.ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const dispatch = useDispatch();
  const [isInitialized, setIsInitialized] = useState(false);
  
  const [verifyToken] = useVerifyTokenMutation();
  const {
    data: currentUser,
    error: userError,
    isLoading: isUserLoading,
  } = useGetCurrentUserQuery(undefined, {
    skip: !isInitialized,
  });

  useEffect(() => {
    const initializeAuth = async () => {
      dispatch(setLoading(true));
      
      try {
        const tokens = tokenStorage.get();
        
        if (!tokens || !tokens.access) {
          // No tokens found, user is not authenticated
          dispatch(clearCredentials());
          setIsInitialized(true);
          return;
        }

        // Check if access token is expired
        if (isTokenExpired(tokens.access)) {
          // Try to refresh with refresh token
          if (tokens.refresh && !isTokenExpired(tokens.refresh)) {
            // The refresh will be handled by the baseQueryWithReauth
            // Just trigger a user query which will attempt refresh
            setIsInitialized(true);
            return;
          } else {
            // Both tokens expired, clear auth
            tokenStorage.remove();
            dispatch(clearCredentials());
            setIsInitialized(true);
            return;
          }
        }

        // Verify token is still valid on server
        try {
          await verifyToken({ token: tokens.access }).unwrap();
          // Token is valid, trigger user query
          setIsInitialized(true);
        } catch (error) {
          // Token invalid on server, clear auth
          tokenStorage.remove();
          dispatch(clearCredentials());
          setIsInitialized(true);
        }
      } catch (error) {
        console.error('Auth initialization error:', error);
        tokenStorage.remove();
        dispatch(clearCredentials());
        setIsInitialized(true);
      }
    };

    initializeAuth();
  }, [dispatch, verifyToken]);

  // Handle user query results
  useEffect(() => {
    if (isInitialized && !isUserLoading) {
      if (currentUser && !userError) {
        const tokens = tokenStorage.get();
        if (tokens) {
          dispatch(setCredentials({
            user: currentUser,
            tokens,
          }));
        }
      } else if (userError) {
        // User query failed, clear auth
        tokenStorage.remove();
        dispatch(clearCredentials());
      }
      dispatch(setLoading(false));
    }
  }, [dispatch, currentUser, userError, isUserLoading, isInitialized]);

  // Show loading screen while initializing
  if (!isInitialized || isUserLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
        <div className="text-center">
          {/* WorldLink Logo */}
          <div className="mx-auto w-16 h-16 bg-gradient-to-br from-blue-600 to-indigo-700 rounded-xl flex items-center justify-center mb-4 shadow-lg">
            <span className="text-white text-xl font-bold">WL</span>
          </div>
          
          <div className="w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          
          <h2 className="text-xl font-semibold text-gray-900 mb-2">
            WorldLink NMS
          </h2>
          <p className="text-gray-600">
            Initializing application...
          </p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};