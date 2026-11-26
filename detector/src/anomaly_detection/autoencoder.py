
import torch
from torch import nn


class Autoencoder(nn.Module):
    def __init__(self, input_dim: int):
        super().__init__()

        hidden_dim = max(16, input_dim // 2)
        latent_dim = max(4, input_dim // 4)

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, latent_dim),
            nn.ReLU(),
        )

        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encoder(x)
        return self.decoder(latent)
