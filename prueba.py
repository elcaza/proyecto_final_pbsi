import plotly.graph_objects as go

etiquetas = ['Oxygen','Hydrogen','Carbon_Dioxide','Nitrogen']
valores = [4500, 2500, 1053, 500]

fuzzing_diagrama = go.Figure(data=[go.Pie(labels=etiquetas, values=valores)])
fuzzing_diagrama.show()