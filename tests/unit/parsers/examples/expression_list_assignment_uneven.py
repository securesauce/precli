import torch


torch.tensor([[0.1, 1.2], [2.2, 3.1], [4.9, 5.2]])
x = torch.tensor([[0.1, 1.2], [2.2, 3.1], [4.9, 5.2]])
b, *_, device = *x.shape, x.device
