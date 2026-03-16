"""
Advanced Network Anomaly Detection Module
Implements multiple ML algorithms for comprehensive network security analysis
"""
from __future__ import annotations

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, RobustScaler, MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split, GridSearchCV
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
from typing import Dict, List, Tuple, Optional, Any, Union
import joblib
from datetime import datetime, timedelta
import logging


try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.layers import Dense, Input, Dropout, LSTM, Conv1D, MaxPooling1D, Flatten, RepeatVector, TimeDistributed
    from tensorflow.keras.optimizers import Adam
    from tensorflow.keras.callbacks import EarlyStopping
    TENSORFLOW_AVAILABLE = True
except ImportError:
    print("Warning: TensorFlow not available. Install with: pip install tensorflow")
    TENSORFLOW_AVAILABLE = False

warnings.filterwarnings('ignore')

class NetworkAnomalyDetector:
    """Comprehensive network anomaly detection system using multiple ML approaches"""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the anomaly detector
        
        Args:
            config: Configuration dictionary for model parameters
        """
        self.config = config or self._get_default_config()
        self.models = {}
        self.scalers = {}
        self.feature_columns = []
        self.results = {}
        self.is_trained = False
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
    def _get_default_config(self) -> Dict:
        """Get default configuration for all models"""
        return {
            'isolation_forest': {
                'contamination': 0.1,
                'n_estimators': 100,
                'random_state': 42,
                'n_jobs': -1
            },
            'one_class_svm': {
                'nu': 0.1,
                'kernel': 'rbf',
                'gamma': 'scale'
            },
            'dbscan': {
                'eps': 0.5,
                'min_samples': 5,
                'n_jobs': -1
            },
            'autoencoder': {
                'encoding_dim': 32,
                'epochs': 50,
                'batch_size': 32,
                'validation_split': 0.2,
                'threshold_percentile': 95
            },
            'lstm_autoencoder': {
                'sequence_length': 10,
                'encoding_dim': 50,
                'epochs': 50,
                'batch_size': 32
            },
            'ensemble': {
                'voting': 'soft',  # 'hard' or 'soft'
                'weights': [0.25, 0.25, 0.25, 0.25]  # Weights for each model
            }
        }
    
    def preprocess_data(self, df: pd.DataFrame, target_col: Optional[str] = None) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """
        Preprocess data for anomaly detection
        
        Args:
            df: Input DataFrame
            target_col: Optional target column name for supervised learning
            
        Returns:
            Tuple of (features, labels)
        """
        self.logger.info("Preprocessing data for anomaly detection...")
        
        # Remove non-numeric columns and handle missing values
        numeric_df = df.select_dtypes(include=[np.number]).fillna(0)
        
        # Remove columns with zero variance
        variance_filter = numeric_df.var() != 0
        numeric_df = numeric_df.loc[:, variance_filter]
        
        # Store feature columns
        if target_col and target_col in numeric_df.columns:
            y = numeric_df[target_col].values
            X = numeric_df.drop(columns=[target_col])
        else:
            y = None
            X = numeric_df
            
        self.feature_columns = X.columns.tolist()
        
        # Handle infinite values
        X = X.replace([np.inf, -np.inf], 0)
        
        # Feature scaling
        if 'scaler' not in self.scalers:
            self.scalers['scaler'] = RobustScaler()
            X_scaled = self.scalers['scaler'].fit_transform(X)
        else:
            X_scaled = self.scalers['scaler'].transform(X)
            
        self.logger.info(f"Preprocessed data shape: {X_scaled.shape}")
        return X_scaled, y
    
    def train_isolation_forest(self, X: np.ndarray) -> IsolationForest:
        """Train Isolation Forest model"""
        self.logger.info("Training Isolation Forest...")
        
        model = IsolationForest(**self.config['isolation_forest'])
        model.fit(X)
        
        # Get anomaly scores
        scores = model.decision_function(X)
        predictions = model.predict(X)
        
        self.results['isolation_forest'] = {
            'predictions': predictions,
            'scores': scores,
            'anomalies': np.sum(predictions == -1),
            'anomaly_rate': np.sum(predictions == -1) / len(predictions)
        }
        
        self.logger.info(f"Isolation Forest - Anomalies detected: {self.results['isolation_forest']['anomalies']}")
        return model
    
    def train_one_class_svm(self, X: np.ndarray) -> OneClassSVM:
        """Train One-Class SVM model"""
        self.logger.info("Training One-Class SVM...")
        
        # Use a subset for training if data is large (SVM doesn't scale well)
        if len(X) > 10000:
            idx = np.random.choice(len(X), 10000, replace=False)
            X_train = X[idx]
        else:
            X_train = X
            
        model = OneClassSVM(**self.config['one_class_svm'])
        model.fit(X_train)
        
        # Get predictions for full dataset
        predictions = model.predict(X)
        scores = model.decision_function(X)
        
        self.results['one_class_svm'] = {
            'predictions': predictions,
            'scores': scores,
            'anomalies': np.sum(predictions == -1),
            'anomaly_rate': np.sum(predictions == -1) / len(predictions)
        }
        
        self.logger.info(f"One-Class SVM - Anomalies detected: {self.results['one_class_svm']['anomalies']}")
        return model
    
    def train_dbscan(self, X: np.ndarray) -> DBSCAN:
        """Train DBSCAN clustering model"""
        self.logger.info("Training DBSCAN...")
        
        model = DBSCAN(**self.config['dbscan'])
        cluster_labels = model.fit_predict(X)
        
        # In DBSCAN, -1 indicates noise/anomalies
        predictions = np.where(cluster_labels == -1, -1, 1)
        
        self.results['dbscan'] = {
            'predictions': predictions,
            'cluster_labels': cluster_labels,
            'anomalies': np.sum(predictions == -1),
            'anomaly_rate': np.sum(predictions == -1) / len(predictions),
            'n_clusters': len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)
        }
        
        self.logger.info(f"DBSCAN - Anomalies detected: {self.results['dbscan']['anomalies']}")
        self.logger.info(f"DBSCAN - Number of clusters: {self.results['dbscan']['n_clusters']}")
        return model
    
    def train_autoencoder(self, X: np.ndarray) -> Optional[Model]:
        """Train Autoencoder neural network"""
        if not TENSORFLOW_AVAILABLE:
            self.logger.warning("TensorFlow not available. Skipping autoencoder training.")
            return None
            
        self.logger.info("Training Autoencoder...")
        
        input_dim = X.shape[1]
        encoding_dim = self.config['autoencoder']['encoding_dim']
        
        # Build autoencoder
        input_layer = Input(shape=(input_dim,))
        
        # Encoder
        encoded = Dense(encoding_dim * 2, activation='relu')(input_layer)
        encoded = Dropout(0.2)(encoded)
        encoded = Dense(encoding_dim, activation='relu')(encoded)
        
        # Decoder
        decoded = Dense(encoding_dim * 2, activation='relu')(encoded)
        decoded = Dropout(0.2)(decoded)
        decoded = Dense(input_dim, activation='linear')(decoded)
        
        # Autoencoder model
        autoencoder = Model(input_layer, decoded)
        autoencoder.compile(optimizer=Adam(learning_rate=0.001), loss='mse')
        
        # Train the model
        early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
        
        history = autoencoder.fit(
            X, X,
            epochs=self.config['autoencoder']['epochs'],
            batch_size=self.config['autoencoder']['batch_size'],
            validation_split=self.config['autoencoder']['validation_split'],
            callbacks=[early_stopping],
            verbose=0
        )
        
        # Calculate reconstruction errors
        reconstructions = autoencoder.predict(X, verbose=0)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        
        # Determine threshold for anomalies
        threshold = np.percentile(mse, self.config['autoencoder']['threshold_percentile'])
        predictions = np.where(mse > threshold, -1, 1)
        
        self.results['autoencoder'] = {
            'predictions': predictions,
            'reconstruction_errors': mse,
            'threshold': threshold,
            'anomalies': np.sum(predictions == -1),
            'anomaly_rate': np.sum(predictions == -1) / len(predictions),
            'training_history': history.history
        }
        
        self.logger.info(f"Autoencoder - Anomalies detected: {self.results['autoencoder']['anomalies']}")
        return autoencoder
    
    def train_lstm_autoencoder(self, X: np.ndarray) -> Optional[Model]:
        """Train LSTM Autoencoder for sequence-based anomaly detection"""
        if not TENSORFLOW_AVAILABLE:
            self.logger.warning("TensorFlow not available. Skipping LSTM autoencoder training.")
            return None
            
        self.logger.info("Training LSTM Autoencoder...")
        
        # Create sequences
        seq_length = self.config['lstm_autoencoder']['sequence_length']
        X_sequences = self._create_sequences(X, seq_length)
        
        if len(X_sequences) == 0:
            self.logger.warning("Not enough data for sequence creation. Skipping LSTM autoencoder.")
            return None
        
        timesteps, n_features = X_sequences.shape[1], X_sequences.shape[2]
        encoding_dim = self.config['lstm_autoencoder']['encoding_dim']
        
        # Build LSTM autoencoder
        model = Sequential([
            LSTM(encoding_dim, activation='relu', input_shape=(timesteps, n_features), return_sequences=True),
            LSTM(encoding_dim // 2, activation='relu', return_sequences=False),
            RepeatVector(timesteps),
            LSTM(encoding_dim // 2, activation='relu', return_sequences=True),
            LSTM(encoding_dim, activation='relu', return_sequences=True),
            TimeDistributed(Dense(n_features))
        ])
        
        model.compile(optimizer=Adam(learning_rate=0.001), loss='mse')
        
        # Train the model
        history = model.fit(
            X_sequences, X_sequences,
            epochs=self.config['lstm_autoencoder']['epochs'],
            batch_size=self.config['lstm_autoencoder']['batch_size'],
            validation_split=0.2,
            verbose=0
        )
        
        # Calculate reconstruction errors
        reconstructions = model.predict(X_sequences, verbose=0)
        mse = np.mean(np.power(X_sequences - reconstructions, 2), axis=(1, 2))
        
        # Determine threshold
        threshold = np.percentile(mse, 95)
        predictions = np.where(mse > threshold, -1, 1)
        
        # Extend predictions to match original data length
        full_predictions = np.ones(len(X))
        full_predictions[seq_length-1:] = predictions
        
        self.results['lstm_autoencoder'] = {
            'predictions': full_predictions,
            'reconstruction_errors': mse,
            'threshold': threshold,
            'anomalies': np.sum(full_predictions == -1),
            'anomaly_rate': np.sum(full_predictions == -1) / len(full_predictions)
        }
        
        self.logger.info(f"LSTM Autoencoder - Anomalies detected: {self.results['lstm_autoencoder']['anomalies']}")
        return model
    
    def _create_sequences(self, data: np.ndarray, seq_length: int) -> np.ndarray:
        """Create sequences for LSTM training"""
        if len(data) < seq_length:
            return np.array([])
            
        sequences = []
        for i in range(len(data) - seq_length + 1):
            sequences.append(data[i:(i + seq_length)])
        return np.array(sequences)
    
    def ensemble_predict(self, X: np.ndarray) -> Dict[str, Any]:
        """Create ensemble predictions from all trained models"""
        self.logger.info("Creating ensemble predictions...")
        
        available_models = [model for model in ['isolation_forest', 'one_class_svm', 'dbscan', 'autoencoder'] 
                           if model in self.results]
        
        if not available_models:
            self.logger.warning("No trained models available for ensemble.")
            return {}
        
        # Collect predictions
        predictions_matrix = []
        weights = []
        
        for i, model_name in enumerate(available_models):
            if 'predictions' in self.results[model_name]:
                predictions_matrix.append(self.results[model_name]['predictions'])
                weights.append(self.config['ensemble']['weights'][i] if i < len(self.config['ensemble']['weights']) else 0.25)
        
        predictions_matrix = np.array(predictions_matrix).T
        weights = np.array(weights[:len(available_models)])
        weights = weights / weights.sum()  # Normalize weights
        
        if self.config['ensemble']['voting'] == 'hard':
            # Hard voting (majority)
            ensemble_pred = np.apply_along_axis(lambda x: 1 if np.sum(x == 1) > np.sum(x == -1) else -1, 
                                              axis=1, arr=predictions_matrix)
        else:
            # Soft voting (weighted average)
            # Convert predictions to probabilities (0 for anomaly, 1 for normal)
            probs_matrix = (predictions_matrix + 1) / 2  # Convert -1,1 to 0,1
            weighted_probs = np.average(probs_matrix, axis=1, weights=weights)
            ensemble_pred = np.where(weighted_probs > 0.5, 1, -1)
        
        ensemble_results = {
            'predictions': ensemble_pred,
            'anomalies': np.sum(ensemble_pred == -1),
            'anomaly_rate': np.sum(ensemble_pred == -1) / len(ensemble_pred),
            'model_agreement': self._calculate_model_agreement(predictions_matrix),
            'used_models': available_models
        }
        
        self.results['ensemble'] = ensemble_results
        self.logger.info(f"Ensemble - Anomalies detected: {ensemble_results['anomalies']}")
        return ensemble_results
    
    def _calculate_model_agreement(self, predictions_matrix: np.ndarray) -> float:
        """Calculate agreement between models"""
        agreement_scores = []
        n_models = predictions_matrix.shape[1]
        
        for i in range(len(predictions_matrix)):
            row = predictions_matrix[i]
            agreement = np.sum(row == row[0]) / n_models
            agreement_scores.append(agreement)
        
        return np.mean(agreement_scores)
    
    def fit(self, df: pd.DataFrame, target_col: Optional[str] = None) -> Dict[str, Any]:
        """
        Train all anomaly detection models
        
        Args:
            df: Input DataFrame
            target_col: Optional target column for supervised learning
            
        Returns:
            Dictionary with training results
        """
        self.logger.info("Starting anomaly detection training...")
        
        # Preprocess data
        X, y = self.preprocess_data(df, target_col)
        
        if len(X) == 0:
            self.logger.error("No data available after preprocessing.")
            return {}
        
        # Train models
        try:
            self.models['isolation_forest'] = self.train_isolation_forest(X)
            self.models['one_class_svm'] = self.train_one_class_svm(X)
            self.models['dbscan'] = self.train_dbscan(X)
            
            if TENSORFLOW_AVAILABLE:
                self.models['autoencoder'] = self.train_autoencoder(X)
                # self.models['lstm_autoencoder'] = self.train_lstm_autoencoder(X)
            
            # Create ensemble predictions
            ensemble_results = self.ensemble_predict(X)
            
            self.is_trained = True
            self.logger.info("Training completed successfully!")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"Error during training: {str(e)}")
            return {}
    
    def predict(self, df: pd.DataFrame) -> Dict[str, np.ndarray]:
        """
        Predict anomalies using trained models
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary with predictions from all models
        """
        if not self.is_trained:
            raise ValueError("Models must be trained before making predictions")
        
        X, _ = self.preprocess_data(df)
        predictions = {}
        
        # Get predictions from each model
        for model_name, model in self.models.items():
            if model is None:
                continue
                
            try:
                if model_name == 'isolation_forest':
                    predictions[model_name] = model.predict(X)
                elif model_name == 'one_class_svm':
                    predictions[model_name] = model.predict(X)
                elif model_name == 'dbscan':
                    cluster_labels = model.fit_predict(X)  # DBSCAN needs fit_predict
                    predictions[model_name] = np.where(cluster_labels == -1, -1, 1)
                elif model_name == 'autoencoder' and TENSORFLOW_AVAILABLE:
                    reconstructions = model.predict(X, verbose=0)
                    mse = np.mean(np.power(X - reconstructions, 2), axis=1)
                    threshold = self.results['autoencoder']['threshold']
                    predictions[model_name] = np.where(mse > threshold, -1, 1)
                    
            except Exception as e:
                self.logger.warning(f"Error predicting with {model_name}: {str(e)}")
        
        return predictions
    
    def get_feature_importance(self, df: pd.DataFrame) -> Dict[str, np.ndarray]:
        """
        Calculate feature importance for anomaly detection
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary with feature importance scores
        """
        if not self.is_trained:
            raise ValueError("Models must be trained before calculating feature importance")
        
        X, _ = self.preprocess_data(df)
        importance_scores = {}
        
        # Isolation Forest feature importance
        if 'isolation_forest' in self.models:
            rf_temp = RandomForestClassifier(n_estimators=100, random_state=42)
            # Create temporary labels based on Isolation Forest predictions
            temp_labels = self.results['isolation_forest']['predictions']
            temp_labels = np.where(temp_labels == -1, 1, 0)  # Convert to binary
            rf_temp.fit(X, temp_labels)
            importance_scores['isolation_forest'] = rf_temp.feature_importances_
        
        # For autoencoders, calculate reconstruction error contribution by feature
        if 'autoencoder' in self.models and self.models['autoencoder'] is not None:
            model = self.models['autoencoder']
            reconstructions = model.predict(X, verbose=0)
            feature_errors = np.mean(np.power(X - reconstructions, 2), axis=0)
            feature_errors = feature_errors / np.sum(feature_errors)  # Normalize
            importance_scores['autoencoder'] = feature_errors
        
        return importance_scores
    
    def generate_report(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Generate comprehensive anomaly detection report
        
        Args:
            df: Input DataFrame
            
        Returns:
            Comprehensive report dictionary
        """
        if not self.is_trained:
            raise ValueError("Models must be trained before generating report")
        
        self.logger.info("Generating anomaly detection report...")
        
        report = {
            'summary': {},
            'model_results': self.results,
            'feature_importance': self.get_feature_importance(df),
            'anomaly_analysis': {},
            'recommendations': []
        }
        
        # Summary statistics
        total_samples = len(df)
        
        for model_name, results in self.results.items():
            if 'anomalies' in results:
                report['summary'][model_name] = {
                    'total_anomalies': results['anomalies'],
                    'anomaly_percentage': results['anomaly_rate'] * 100,
                    'normal_samples': total_samples - results['anomalies']
                }
        
        # Anomaly analysis
        if 'ensemble' in self.results:
            ensemble_pred = self.results['ensemble']['predictions']
            anomaly_indices = np.where(ensemble_pred == -1)[0]
            
            if len(anomaly_indices) > 0:
                X, _ = self.preprocess_data(df)
                anomaly_samples = X[anomaly_indices]
                normal_samples = X[ensemble_pred == 1]
                
                report['anomaly_analysis'] = {
                    'anomaly_feature_means': np.mean(anomaly_samples, axis=0).tolist(),
                    'normal_feature_means': np.mean(normal_samples, axis=0).tolist(),
                    'feature_differences': (np.mean(anomaly_samples, axis=0) - np.mean(normal_samples, axis=0)).tolist(),
                    'top_anomaly_features': self._get_top_anomaly_features(anomaly_samples, normal_samples)
                }
        
        # Generate recommendations
        report['recommendations'] = self._generate_recommendations(report)
        
        self.logger.info("Report generated successfully!")
        return report
    
    def _get_top_anomaly_features(self, anomaly_samples: np.ndarray, normal_samples: np.ndarray, top_k: int = 10) -> List[Dict]:
        """Get top features that distinguish anomalies from normal samples"""
        if len(anomaly_samples) == 0 or len(normal_samples) == 0:
            return []
        
        # Calculate statistical differences
        anomaly_means = np.mean(anomaly_samples, axis=0)
        normal_means = np.mean(normal_samples, axis=0)
        differences = np.abs(anomaly_means - normal_means)
        
        # Get top features
        top_indices = np.argsort(differences)[-top_k:][::-1]
        
        top_features = []
        for idx in top_indices:
            if idx < len(self.feature_columns):
                top_features.append({
                    'feature': self.feature_columns[idx],
                    'anomaly_mean': float(anomaly_means[idx]),
                    'normal_mean': float(normal_means[idx]),
                    'difference': float(differences[idx])
                })
        
        return top_features
    
    def _generate_recommendations(self, report: Dict) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        # Check ensemble agreement
        if 'ensemble' in self.results:
            agreement = self.results['ensemble'].get('model_agreement', 0)
            if agreement < 0.7:
                recommendations.append("Low model agreement detected. Consider reviewing feature engineering or model parameters.")
        
        # Check anomaly rates
        for model_name, summary in report['summary'].items():
            anomaly_rate = summary.get('anomaly_percentage', 0)
            if anomaly_rate > 20:
                recommendations.append(f"High anomaly rate ({anomaly_rate:.1f}%) detected by {model_name}. Review contamination parameters.")
            elif anomaly_rate < 1:
                recommendations.append(f"Very low anomaly rate ({anomaly_rate:.1f}%) detected by {model_name}. Consider adjusting sensitivity.")
        
        # Feature-based recommendations
        if 'anomaly_analysis' in report and 'top_anomaly_features' in report['anomaly_analysis']:
            top_features = report['anomaly_analysis']['top_anomaly_features'][:3]
            if top_features:
                feature_names = [f['feature'] for f in top_features]
                recommendations.append(f"Focus monitoring on these key distinguishing features: {', '.join(feature_names)}")
        
        return recommendations
    
    def save_models(self, filepath: str) -> bool:
        """Save trained models and scalers"""
        try:
            save_data = {
                'models': {},
                'scalers': self.scalers,
                'feature_columns': self.feature_columns,
                'results': self.results,
                'config': self.config,
                'is_trained': self.is_trained
            }
            
            # Save non-neural network models
            for name, model in self.models.items():
                if name not in ['autoencoder', 'lstm_autoencoder']:
                    save_data['models'][name] = model
            
            joblib.dump(save_data, f"{filepath}_traditional_models.pkl")
            
            # Save neural network models separately
            if 'autoencoder' in self.models and self.models['autoencoder'] is not None:
                self.models['autoencoder'].save(f"{filepath}_autoencoder.h5")
            
            self.logger.info(f"Models saved successfully to {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving models: {str(e)}")
            return False
    
    def load_models(self, filepath: str) -> bool:
        """Load trained models and scalers"""
        try:
            # Load traditional models
            save_data = joblib.load(f"{filepath}_traditional_models.pkl")
            
            self.models.update(save_data['models'])
            self.scalers = save_data['scalers']
            self.feature_columns = save_data['feature_columns']
            self.results = save_data['results']
            self.config = save_data['config']
            self.is_trained = save_data['is_trained']
            
            # Load neural network models
            if TENSORFLOW_AVAILABLE:
                try:
                    self.models['autoencoder'] = tf.keras.models.load_model(f"{filepath}_autoencoder.h5")
                except:
                    pass  # File might not exist
            
            self.logger.info(f"Models loaded successfully from {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading models: {str(e)}")
            return False


# Example usage
if __name__ == "__main__":
    # Create sample data
    np.random.seed(42)
    n_samples = 1000
    n_features = 10
    
    # Normal data
    normal_data = np.random.normal(0, 1, (n_samples, n_features))
    
    # Add some anomalies
    n_anomalies = 50
    anomaly_indices = np.random.choice(n_samples, n_anomalies, replace=False)
    normal_data[anomaly_indices] += np.random.normal(3, 1, (n_anomalies, n_features))
    
    # Create DataFrame
    feature_names = [f'feature_{i}' for i in range(n_features)]
    df = pd.DataFrame(normal_data, columns=feature_names)
    
    # Initialize and train detector
    detector = NetworkAnomalyDetector()
    results = detector.fit(df)
    
    # Generate report
    report = detector.generate_report(df)
    
    print("Anomaly Detection Results:")
    for model, result in results.items():
        if 'anomalies' in result:
            print(f"{model}: {result['anomalies']} anomalies ({result['anomaly_rate']*100:.2f}%)")
    
    print(f"\nRecommendations:")
    for rec in report['recommendations']:
        print(f"- {rec}")
